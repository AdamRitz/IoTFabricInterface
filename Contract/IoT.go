package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/expr-lang/expr"
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
	Description string `json:"description,omitempty"`
	UpdatedTxID string `json:"updatedTxId"`
	UpdatedAt   string `json:"updatedAt"`
}

type DeviceData struct {
	DeviceID string         `json:"deviceId"`
	Fields   map[string]any `json:"fields"`
}

type RuleResult struct {
	RuleID     string `json:"ruleId"`
	Expression string `json:"expression"`
	Passed     bool   `json:"passed"`
	Error      string `json:"error,omitempty"`
}

type DataRecord struct {
	TxID        string         `json:"txId"`
	DeviceID    string         `json:"deviceId"`
	Fields      map[string]any `json:"fields"`
	Results     []RuleResult   `json:"results"`
	SubmittedAt string         `json:"submittedAt"`
}

func normalizeJSONValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, v2 := range x {
			out[k] = normalizeJSONValue(v2)
		}
		return out

	case []any:
		out := make([]any, len(x))
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

	_, err := expr.Compile(
		expression,
		expr.Env(map[string]any{"deviceId": "", "has": func(string) bool { return false }}), expr.AsBool(), expr.AllowUndefinedVariables(), expr.DisableAllBuiltins(),
	)
	if err != nil {
		return fmt.Errorf("invalid expr rule: %w", err)
	}

	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %w", err)
	}

	rule := Rule{ruleID, expression, description, ctx.GetStub().GetTxID(), time.Unix(ts.Seconds, int64(ts.Nanos)).UTC().Format(time.RFC3339Nano)}

	raw, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule: %w", err)
	}
	// 存储的是 rule:ID
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
			return fmt.Errorf("failed to delete device reverse binding: %w", err)
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
		return fmt.Errorf("failed to create device reverse binding key: %w", err)
	}
	if err := ctx.GetStub().PutState(reverseKey, []byte{0}); err != nil {
		return fmt.Errorf("failed to save device reverse binding: %w", err)
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
		return fmt.Errorf("failed to create device reverse binding key: %w", err)
	}
	if err := ctx.GetStub().DelState(reverseKey); err != nil {
		return fmt.Errorf("failed to delete device reverse binding: %w", err)
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
	// 解析 JSON 数据
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
		data.Fields = map[string]any{}
	}

	normalized, ok := normalizeJSONValue(data.Fields).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("fields must be a json object")
	}
	data.Fields = normalized
	// 按 ID 查找规则
	rules, err := c.ListRulesForDevice(ctx, data.DeviceID)
	if err != nil {
		return nil, err
	}

	env := map[string]any{
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
	// 编译并执行规则
	for _, rule := range rules {
		// 编译规则
		program, err := expr.Compile(
			rule.Expression,
			expr.Env(map[string]any{"deviceId": "", "has": func(string) bool { return false }}), expr.AsBool(), expr.AllowUndefinedVariables(), expr.DisableAllBuiltins(),
		)
		if err != nil {
			results = append(results, RuleResult{
				RuleID:     rule.RuleID,
				Expression: rule.Expression,
				Passed:     false,
				Error:      err.Error(),
			})
			continue
		}
		// 执行规则
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

		passed, ok := out.(bool)
		if !ok {
			results = append(results, RuleResult{
				RuleID:     rule.RuleID,
				Expression: rule.Expression,
				Passed:     false,
				Error:      "expr result is not bool",
			})
			continue
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
