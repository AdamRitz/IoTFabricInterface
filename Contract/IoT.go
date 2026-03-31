package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	DeviceToRule = "bind~deviceId~ruleId"
	RuleToDevice = "bind~ruleId~deviceId"
)

type SmartContract struct {
	contractapi.Contract
}

type Rule struct {
	RuleID      string `json:"ruleId"`
	Expression  string `json:"expression"`
	Description string `json:"description"`
	UpdatedTxID string `json:"updatedTxId"`
	UpdatedAt   string `json:"updatedAt"`
}

type DeviceData struct {
	DeviceID string                 `json:"deviceId"`
	Fields   map[string]interface{} `json:"fields"`
}

type RuleResult struct {
	RuleID     string `json:"ruleId"`
	Expression string `json:"expression"`
	Passed     bool   `json:"passed"`
	Error      string `json:"error"`
}

type DataRecord struct {
	TxID        string                 `json:"txId"`
	DeviceID    string                 `json:"deviceId"`
	Fields      map[string]interface{} `json:"fields"`
	Results     []RuleResult           `json:"results"`
	SubmittedAt string                 `json:"submittedAt"`
}

func normalizeJSONValue(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, v2 := range x {
			out[k] = normalizeJSONValue(v2)
		}
		return out

	case []interface{}:
		out := make([]interface{}, len(x))
		for i, v2 := range x {
			out[i] = normalizeJSONValue(v2)
		}
		return out

	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		if f, err := x.Float64(); err == nil {
			return f
		}
		return x.String()

	default:
		return v
	}
}

func buildCompileEnv() map[string]interface{} {
	return map[string]interface{}{
		"deviceId": "",
		"has": func(string) bool {
			return false
		},
	}
}

func compileRule(expression string) (*vm.Program, error) {
	return expr.Compile(
		expression,
		expr.Env(buildCompileEnv()),
		expr.AsBool(),
		expr.AllowUndefinedVariables(),
	)
}

func (c *SmartContract) UpsertRule(
	ctx contractapi.TransactionContextInterface,
	ruleID string,
	expression string,
	description string,
) error {
	if ruleID == "" {
		return fmt.Errorf("ruleId is required")
	}
	if expression == "" {
		return fmt.Errorf("expression is required")
	}

	_, err := compileRule(expression)
	if err != nil {
		return fmt.Errorf("invalid expr rule: %w", err)
	}

	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %w", err)
	}

	rule := Rule{
		RuleID:      ruleID,
		Expression:  expression,
		Description: description,
		UpdatedTxID: ctx.GetStub().GetTxID(),
		UpdatedAt:   time.Unix(ts.Seconds, int64(ts.Nanos)).UTC().Format(time.RFC3339Nano),
	}

	raw, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule: %w", err)
	}

	if err := ctx.GetStub().PutState("rule:"+ruleID, raw); err != nil {
		return fmt.Errorf("failed to save rule: %w", err)
	}

	return nil
}

func (c *SmartContract) DeleteRule(ctx contractapi.TransactionContextInterface, ruleID string) error {
	raw, err := ctx.GetStub().GetState("rule:" + ruleID)
	if err != nil {
		return fmt.Errorf("failed to read rule: %w", err)
	}
	if raw == nil {
		return fmt.Errorf("rule %s does not exist", ruleID)
	}

	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(RuleToDevice, []string{ruleID})
	if err != nil {
		return fmt.Errorf("failed to query rule-device bindings: %w", err)
	}
	defer iter.Close()

	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return fmt.Errorf("failed to iterate rule-device bindings: %w", err)
		}

		_, parts, err := ctx.GetStub().SplitCompositeKey(kv.Key)
		if err != nil {
			return fmt.Errorf("failed to split rule-device binding key: %w", err)
		}
		if len(parts) != 2 {
			continue
		}

		deviceID := parts[1]

		forwardKey, err := ctx.GetStub().CreateCompositeKey(DeviceToRule, []string{deviceID, ruleID})
		if err != nil {
			return fmt.Errorf("failed to create device forward binding key: %w", err)
		}
		if err := ctx.GetStub().DelState(forwardKey); err != nil {
			return fmt.Errorf("failed to delete device forward binding: %w", err)
		}

		if err := ctx.GetStub().DelState(kv.Key); err != nil {
			return fmt.Errorf("failed to delete rule reverse binding: %w", err)
		}
	}

	if err := ctx.GetStub().DelState("rule:" + ruleID); err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	return nil
}

func (c *SmartContract) GetRule(ctx contractapi.TransactionContextInterface, ruleID string) (*Rule, error) {
	raw, err := ctx.GetStub().GetState("rule:" + ruleID)
	if err != nil {
		return nil, fmt.Errorf("failed to read rule: %w", err)
	}
	if raw == nil {
		return nil, fmt.Errorf("rule %s does not exist", ruleID)
	}

	var rule Rule
	if err := json.Unmarshal(raw, &rule); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rule: %w", err)
	}

	return &rule, nil
}

func (c *SmartContract) ListAllRules(ctx contractapi.TransactionContextInterface) ([]Rule, error) {
	iter, err := ctx.GetStub().GetStateByRange("rule:", "rule;")
	if err != nil {
		return nil, fmt.Errorf("failed to query all rules: %w", err)
	}
	defer iter.Close()

	rules := make([]Rule, 0)
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate all rules: %w", err)
		}

		var rule Rule
		if err := json.Unmarshal(kv.Value, &rule); err != nil {
			return nil, fmt.Errorf("failed to unmarshal rule from key %s: %w", kv.Key, err)
		}
		rules = append(rules, rule)
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].RuleID < rules[j].RuleID
	})

	return rules, nil
}

func (c *SmartContract) BindRuleToDevice(
	ctx contractapi.TransactionContextInterface,
	ruleID string,
	deviceID string,
) error {
	if ruleID == "" {
		return fmt.Errorf("ruleId is required")
	}
	if deviceID == "" {
		return fmt.Errorf("deviceId is required")
	}

	raw, err := ctx.GetStub().GetState("rule:" + ruleID)
	if err != nil {
		return fmt.Errorf("failed to read rule: %w", err)
	}
	if raw == nil {
		return fmt.Errorf("rule %s does not exist", ruleID)
	}

	forwardKey, err := ctx.GetStub().CreateCompositeKey(DeviceToRule, []string{deviceID, ruleID})
	if err != nil {
		return fmt.Errorf("failed to create device forward binding key: %w", err)
	}
	if err := ctx.GetStub().PutState(forwardKey, []byte{0}); err != nil {
		return fmt.Errorf("failed to save device forward binding: %w", err)
	}

	reverseKey, err := ctx.GetStub().CreateCompositeKey(RuleToDevice, []string{ruleID, deviceID})
	if err != nil {
		return fmt.Errorf("failed to create rule reverse binding key: %w", err)
	}
	if err := ctx.GetStub().PutState(reverseKey, []byte{0}); err != nil {
		return fmt.Errorf("failed to save rule reverse binding: %w", err)
	}

	return nil
}

func (c *SmartContract) UnbindRuleFromDevice(
	ctx contractapi.TransactionContextInterface,
	ruleID string,
	deviceID string,
) error {
	if ruleID == "" {
		return fmt.Errorf("ruleId is required")
	}
	if deviceID == "" {
		return fmt.Errorf("deviceId is required")
	}

	forwardKey, err := ctx.GetStub().CreateCompositeKey(DeviceToRule, []string{deviceID, ruleID})
	if err != nil {
		return fmt.Errorf("failed to create device forward binding key: %w", err)
	}
	if err := ctx.GetStub().DelState(forwardKey); err != nil {
		return fmt.Errorf("failed to delete device forward binding: %w", err)
	}

	reverseKey, err := ctx.GetStub().CreateCompositeKey(RuleToDevice, []string{ruleID, deviceID})
	if err != nil {
		return fmt.Errorf("failed to create rule reverse binding key: %w", err)
	}
	if err := ctx.GetStub().DelState(reverseKey); err != nil {
		return fmt.Errorf("failed to delete rule reverse binding: %w", err)
	}

	return nil
}

func (c *SmartContract) ListRulesForDevice(
	ctx contractapi.TransactionContextInterface,
	deviceID string,
) ([]Rule, error) {
	if deviceID == "" {
		return []Rule{}, nil
	}

	ruleIDs := make(map[string]struct{})

	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(DeviceToRule, []string{deviceID})
	if err != nil {
		return nil, fmt.Errorf("failed to query device bindings: %w", err)
	}
	defer iter.Close()

	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate device bindings: %w", err)
		}

		_, parts, err := ctx.GetStub().SplitCompositeKey(kv.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split device binding key: %w", err)
		}
		if len(parts) != 2 {
			continue
		}

		ruleIDs[parts[1]] = struct{}{}
	}

	rules := make([]Rule, 0, len(ruleIDs))
	for ruleID := range ruleIDs {
		raw, err := ctx.GetStub().GetState("rule:" + ruleID)
		if err != nil {
			return nil, fmt.Errorf("failed to read rule %s: %w", ruleID, err)
		}
		if raw == nil {
			continue
		}

		var rule Rule
		if err := json.Unmarshal(raw, &rule); err != nil {
			return nil, fmt.Errorf("failed to unmarshal rule %s: %w", ruleID, err)
		}

		rules = append(rules, rule)
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].RuleID < rules[j].RuleID
	})

	return rules, nil
}

func (c *SmartContract) SubmitData(
	ctx contractapi.TransactionContextInterface,
	dataJSON string,
) (*DataRecord, error) {
	var data DeviceData

	dec := json.NewDecoder(bytes.NewBufferString(dataJSON))
	dec.UseNumber()

	if err := dec.Decode(&data); err != nil {
		return nil, fmt.Errorf("invalid data json: %w", err)
	}

	if data.DeviceID == "" {
		return nil, fmt.Errorf("deviceId is required")
	}

	if data.Fields == nil {
		data.Fields = map[string]interface{}{}
	}

	normalized, ok := normalizeJSONValue(data.Fields).(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("fields must be a json object")
	}
	data.Fields = normalized

	rules, err := c.ListRulesForDevice(ctx, data.DeviceID)
	if err != nil {
		return nil, err
	}

	env := map[string]interface{}{
		"deviceId": data.DeviceID,
	}
	for k, v := range data.Fields {
		env[k] = v
	}
	env["has"] = func(name string) bool {
		_, ok := data.Fields[name]
		return ok
	}

	results := make([]RuleResult, 0, len(rules))

	for _, rule := range rules {
		// 取出编译规则
		program, err := compileRule(rule.Expression)
		if err != nil {
			results = append(results, RuleResult{
				RuleID:     rule.RuleID,
				Expression: rule.Expression,
				Passed:     false,
				Error:      err.Error(),
			})
			continue
		}
		// 运行规则
		out, err := expr.Run(program, env)
		if err != nil {
			results = append(results, RuleResult{
				RuleID:     rule.RuleID,
				Expression: rule.Expression,
				Passed:     false,
				Error:      err.Error(),
			})
			continue
		}
		// 执行结果为真就发送事件
		passed, ok := out.(bool)
		if !ok {
			results = append(results, RuleResult{
				RuleID:     rule.RuleID,
				Expression: rule.Expression,
				Passed:     false,
				Error:      fmt.Sprintf("expr result is not bool, got %T", out),
			})
			continue
		}
		if passed {
			ctx.GetStub().SetEvent(data.DeviceID, []byte(rule.RuleID))
		}

		results = append(results, RuleResult{
			RuleID:     rule.RuleID,
			Expression: rule.Expression,
			Passed:     passed,
		})
	}

	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return nil, fmt.Errorf("failed to get tx timestamp: %w", err)
	}

	record := &DataRecord{
		TxID:        ctx.GetStub().GetTxID(),
		DeviceID:    data.DeviceID,
		Fields:      data.Fields,
		Results:     results,
		SubmittedAt: time.Unix(ts.Seconds, int64(ts.Nanos)).UTC().Format(time.RFC3339Nano),
	}

	raw, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data record: %w", err)
	}

	if err := ctx.GetStub().PutState("data:"+record.TxID, raw); err != nil {
		return nil, fmt.Errorf("failed to save data record: %w", err)
	}

	return record, nil
}

func (c *SmartContract) GetData(ctx contractapi.TransactionContextInterface, txID string) (*DataRecord, error) {
	raw, err := ctx.GetStub().GetState("data:" + txID)
	if err != nil {
		return nil, fmt.Errorf("failed to read data record: %w", err)
	}
	if raw == nil {
		return nil, fmt.Errorf("data record %s does not exist", txID)
	}

	var record DataRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data record: %w", err)
	}

	return &record, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		panic(fmt.Errorf("failed to create chaincode: %w", err))
	}

	if err := chaincode.Start(); err != nil {
		panic(fmt.Errorf("failed to start chaincode: %w", err))
	}
}
