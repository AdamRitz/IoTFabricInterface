package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	DeviceToRule       = "bind~deviceId~ruleId"
	RuleToDevice       = "bind~ruleId~deviceId"
	DataByTime         = "idx~data~time~txId"
	DataByDevice       = "idx~data~deviceId~time~txId"
	DataPageSize int32 = 10
	maxInt64     int64 = 1<<63 - 1
)

type SmartContract struct{ contractapi.Contract }

type Rule struct {
	RuleID      string `json:"ruleId"`
	Expression  string `json:"expression"`
	Description string `json:"description"`
	UpdatedTxID string `json:"updatedTxId"`
	UpdatedAt   string `json:"updatedAt"`
}

type RuleResult struct {
	RuleID     string `json:"ruleId"`
	Expression string `json:"expression"`
	Match      bool   `json:"match"`
	Error      string `json:"error"`
}

type DataRecord struct {
	TxID            string                 `json:"txId"`
	DeviceID        string                 `json:"deviceId"`
	Fields          map[string]interface{} `json:"fields"`
	Results         []RuleResult           `json:"results"`
	SubmittedAt     string                 `json:"submittedAt"`
	SubmittedAtUnix int64                  `json:"submittedAtUnix"`
	SubmitterID     string                 `json:"submitterId"`
	SubmitterMSP    string                 `json:"submitterMsp"`
}

type DataPage struct {
	Records             []DataRecord `json:"records"`
	Bookmark            string       `json:"bookmark"`
	FetchedRecordsCount int32        `json:"fetchedRecordsCount"`
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

func reverseTimeKey(unixNano int64) string { return fmt.Sprintf("%019d", maxInt64-unixNano) }

func (c *SmartContract) getDataByTxID(ctx contractapi.TransactionContextInterface, txID string) (*DataRecord, error) {
	raw, err := ctx.GetStub().GetState("data:" + txID)
	if err != nil {
		return nil, fmt.Errorf("failed to read data record %s: %w", txID, err)
	}
	if raw == nil {
		return nil, nil
	}
	var record DataRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data record %s: %w", txID, err)
	}
	return &record, nil
}

func (c *SmartContract) UpsertRule(ctx contractapi.TransactionContextInterface, ruleID, expression, description string) error {
	if ruleID == "" {
		return fmt.Errorf("ruleId is required")
	}
	if expression == "" {
		return fmt.Errorf("expression is required")
	}

	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %w", err)
	}

	rule := Rule{RuleID: ruleID, Expression: expression, Description: description, UpdatedTxID: ctx.GetStub().GetTxID(), UpdatedAt: time.Unix(ts.Seconds, int64(ts.Nanos)).UTC().Format(time.RFC3339Nano)}
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

	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })
	return rules, nil
}

func (c *SmartContract) BindRuleToDevice(ctx contractapi.TransactionContextInterface, ruleID, deviceID string) error {
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

func (c *SmartContract) UnbindRuleFromDevice(ctx contractapi.TransactionContextInterface, ruleID, deviceID string) error {
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

func (c *SmartContract) ListRulesForDevice(ctx contractapi.TransactionContextInterface, deviceID string) ([]Rule, error) {
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

	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })
	return rules, nil
}

func (c *SmartContract) SubmitData(ctx contractapi.TransactionContextInterface, deviceID, fieldsJSON, resultsJSON string) (*DataRecord, error) {
	deviceID = string(bytes.TrimSpace([]byte(deviceID)))
	if deviceID == "" {
		return nil, fmt.Errorf("deviceId is required")
	}

	fields := map[string]interface{}{}
	if string(bytes.TrimSpace([]byte(fieldsJSON))) != "" {
		dec := json.NewDecoder(bytes.NewBufferString(fieldsJSON))
		dec.UseNumber()
		if err := dec.Decode(&fields); err != nil {
			return nil, fmt.Errorf("invalid fields json: %w", err)
		}
	}

	normalized, ok := normalizeJSONValue(fields).(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("fields must be a json object")
	}
	fields = normalized

	results := make([]RuleResult, 0)
	if string(bytes.TrimSpace([]byte(resultsJSON))) != "" {
		if err := json.Unmarshal([]byte(resultsJSON), &results); err != nil {
			return nil, fmt.Errorf("invalid results json: %w", err)
		}
	}

	clientID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return nil, fmt.Errorf("failed to get client id: %w", err)
	}
	clientMSP, err := cid.GetMSPID(ctx.GetStub())
	if err != nil {
		return nil, fmt.Errorf("failed to get client MSP: %w", err)
	}

	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return nil, fmt.Errorf("failed to get tx timestamp: %w", err)
	}

	submittedTime := time.Unix(ts.Seconds, int64(ts.Nanos)).UTC()
	submittedAtUnix := submittedTime.UnixNano()
	txID := ctx.GetStub().GetTxID()
	rk := fmt.Sprintf("%019d", maxInt64-submittedAtUnix)

	record := &DataRecord{TxID: txID, DeviceID: deviceID, Fields: fields, Results: results, SubmittedAt: submittedTime.Format(time.RFC3339Nano), SubmittedAtUnix: submittedAtUnix, SubmitterID: clientID, SubmitterMSP: clientMSP}
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data record: %w", err)
	}
	if err := ctx.GetStub().PutState("data:"+record.TxID, raw); err != nil {
		return nil, fmt.Errorf("failed to save data record: %w", err)
	}

	timeIndexKey, err := ctx.GetStub().CreateCompositeKey(DataByTime, []string{rk, txID})
	if err != nil {
		return nil, fmt.Errorf("failed to create data-time index key: %w", err)
	}
	if err := ctx.GetStub().PutState(timeIndexKey, []byte{0}); err != nil {
		return nil, fmt.Errorf("failed to save data-time index: %w", err)
	}

	deviceIndexKey, err := ctx.GetStub().CreateCompositeKey(DataByDevice, []string{deviceID, rk, txID})
	if err != nil {
		return nil, fmt.Errorf("failed to create data-device index key: %w", err)
	}
	if err := ctx.GetStub().PutState(deviceIndexKey, []byte{0}); err != nil {
		return nil, fmt.Errorf("failed to save data-device index: %w", err)
	}

	return record, nil
}

func (c *SmartContract) GetData(ctx contractapi.TransactionContextInterface, txID string) (*DataRecord, error) {
	record, err := c.getDataByTxID(ctx, txID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("data record %s does not exist", txID)
	}
	return record, nil
}

func (c *SmartContract) QueryDataPageByTime(ctx contractapi.TransactionContextInterface, bookmark string) (*DataPage, error) {
	iter, metadata, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(DataByTime, []string{}, DataPageSize, bookmark)
	if err != nil {
		return nil, fmt.Errorf("failed to query data page by time: %w", err)
	}
	defer iter.Close()

	records := make([]DataRecord, 0)
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate data-time index: %w", err)
		}
		_, parts, err := ctx.GetStub().SplitCompositeKey(kv.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split data-time index key: %w", err)
		}
		if len(parts) != 2 {
			continue
		}

		txID := parts[1]
		record, err := c.getDataByTxID(ctx, txID)
		if err != nil {
			return nil, err
		}
		if record == nil {
			continue
		}
		records = append(records, *record)
	}

	return &DataPage{Records: records, Bookmark: metadata.Bookmark, FetchedRecordsCount: metadata.FetchedRecordsCount}, nil
}

func (c *SmartContract) QueryDataPageByDevice(ctx contractapi.TransactionContextInterface, deviceID, bookmark string) (*DataPage, error) {
	deviceID = string(bytes.TrimSpace([]byte(deviceID)))
	if deviceID == "" {
		return &DataPage{Records: []DataRecord{}, Bookmark: "", FetchedRecordsCount: 0}, nil
	}

	iter, metadata, err := ctx.GetStub().GetStateByPartialCompositeKeyWithPagination(DataByDevice, []string{deviceID}, DataPageSize, bookmark)
	if err != nil {
		return nil, fmt.Errorf("failed to query data page by device: %w", err)
	}
	defer iter.Close()

	records := make([]DataRecord, 0)
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate data-device index: %w", err)
		}
		_, parts, err := ctx.GetStub().SplitCompositeKey(kv.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split data-device index key: %w", err)
		}
		if len(parts) != 3 {
			continue
		}

		txID := parts[2]
		record, err := c.getDataByTxID(ctx, txID)
		if err != nil {
			return nil, err
		}
		if record == nil {
			continue
		}
		records = append(records, *record)
	}

	return &DataPage{Records: records, Bookmark: metadata.Bookmark, FetchedRecordsCount: metadata.FetchedRecordsCount}, nil
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
