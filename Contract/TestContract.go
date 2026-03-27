package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

//type SmartContract struct {
//	contractapi.Contract
//}

type Condition struct {
	Source string      `json:"source"` // current | state
	Field  string      `json:"field"`
	Op     string      `json:"op"` // eq ne gt gte lt lte
	Value  interface{} `json:"value"`
}

type Action struct {
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	EmitEvent bool   `json:"emitEvent"`
	Reject    bool   `json:"reject"`
}

type Policy struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Enabled    bool        `json:"enabled"`
	EventType  string      `json:"eventType"` // telemetry | command
	Logic      string      `json:"logic"`     // all | any
	Conditions []Condition `json:"conditions"`
	Action     Action      `json:"action"`
	CreatedAt  int64       `json:"createdAt"`
	UpdatedAt  int64       `json:"updatedAt"`
}

type TelemetryRecord struct {
	ID        string                 `json:"id"`
	DeviceID  string                 `json:"deviceId"`
	Timestamp int64                  `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	TxID      string                 `json:"txId"`
}

type CommandRecord struct {
	ID        string                 `json:"id"`
	DeviceID  string                 `json:"deviceId"`
	Timestamp int64                  `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	TxID      string                 `json:"txId"`
}

type DeviceState struct {
	DeviceID     string                 `json:"deviceId"`
	LastValues   map[string]interface{} `json:"lastValues"`
	ValveStatus  map[string]string      `json:"valveStatus"`
	LastCommand  string                 `json:"lastCommand"`
	LastTarget   string                 `json:"lastTarget"`
	LastUpdateAt int64                  `json:"lastUpdateAt"`
}

type AlertRecord struct {
	ID         string                 `json:"id"`
	PolicyID   string                 `json:"policyId"`
	PolicyName string                 `json:"policyName"`
	DeviceID   string                 `json:"deviceId"`
	EventType  string                 `json:"eventType"`
	Severity   string                 `json:"severity"`
	Message    string                 `json:"message"`
	Payload    map[string]interface{} `json:"payload"`
	Timestamp  int64                  `json:"timestamp"`
	TxID       string                 `json:"txId"`
}

type AlertBatchEvent struct {
	DeviceID   string        `json:"deviceId"`
	EventType  string        `json:"eventType"`
	Timestamp  int64         `json:"timestamp"`
	HitCount   int           `json:"hitCount"`
	Rejected   bool          `json:"rejected"`
	AlertIDs   []string      `json:"alertIds"`
	Alerts     []AlertRecord `json:"alerts"`
	RawPayload interface{}   `json:"rawPayload"`
}

func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	return nil
}

// 添加或修改策略
func (s *SmartContract) AddOrUpdatePolicy(ctx contractapi.TransactionContextInterface, policyJSON string) error {
	var p Policy
	if err := json.Unmarshal([]byte(policyJSON), &p); err != nil {
		return fmt.Errorf("parse policy failed: %v", err)
	}
	if p.ID == "" {
		return fmt.Errorf("policy id is required")
	}
	now := time.Now().Unix()
	if p.CreatedAt == 0 {
		p.CreatedAt = now
	}
	p.UpdatedAt = now

	b, _ := json.Marshal(p)
	return ctx.GetStub().PutState("policy:"+p.ID, b)
}

// 作用：查询策略
func (s *SmartContract) GetPolicy(ctx contractapi.TransactionContextInterface, policyID string) (*Policy, error) {
	b, err := ctx.GetStub().GetState("policy:" + policyID)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("policy not found")
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// 提交数据
func (s *SmartContract) SubmitTelemetry(ctx contractapi.TransactionContextInterface, deviceID string, dataJSON string) error {
	if deviceID == "" {
		return fmt.Errorf("deviceID is required")
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(dataJSON), &data); err != nil {
		return fmt.Errorf("parse telemetry failed: %v", err)
	}

	now := time.Now().Unix()
	txID := ctx.GetStub().GetTxID()
	rec := TelemetryRecord{
		ID:        txID,
		DeviceID:  deviceID,
		Timestamp: now,
		Data:      data,
		TxID:      txID,
	}

	recBytes, _ := json.Marshal(rec)
	if err := ctx.GetStub().PutState(fmt.Sprintf("telemetry:%s:%d", deviceID, now), recBytes); err != nil {
		return err
	}

	state, err := s.getOrInitState(ctx, deviceID)
	if err != nil {
		return err
	}
	for k, v := range data {
		state.LastValues[k] = v
	}
	state.LastUpdateAt = now
	if err := s.saveState(ctx, state); err != nil {
		return err
	}

	alerts, rejected, err := s.evaluatePolicies(ctx, "telemetry", deviceID, data, state)
	if err != nil {
		return err
	}
	if len(alerts) > 0 {
		if err := s.emitAlertBatchEvent(ctx, deviceID, "telemetry", data, alerts, rejected); err != nil {
			return err
		}
	}
	return nil
}

// 提交命令
func (s *SmartContract) SubmitCommand(ctx contractapi.TransactionContextInterface, deviceID string, commandJSON string) error {
	if deviceID == "" {
		return fmt.Errorf("deviceID is required")
	}

	var cmd map[string]interface{}
	if err := json.Unmarshal([]byte(commandJSON), &cmd); err != nil {
		return fmt.Errorf("parse command failed: %v", err)
	}

	now := time.Now().Unix()
	txID := ctx.GetStub().GetTxID()
	rec := CommandRecord{
		ID:        txID,
		DeviceID:  deviceID,
		Timestamp: now,
		Data:      cmd,
		TxID:      txID,
	}

	recBytes, _ := json.Marshal(rec)
	if err := ctx.GetStub().PutState(fmt.Sprintf("command:%s:%d", deviceID, now), recBytes); err != nil {
		return err
	}

	state, err := s.getOrInitState(ctx, deviceID)
	if err != nil {
		return err
	}

	alerts, rejected, err := s.evaluatePolicies(ctx, "command", deviceID, cmd, state)
	if err != nil {
		return err
	}

	if len(alerts) > 0 {
		if err := s.emitAlertBatchEvent(ctx, deviceID, "command", cmd, alerts, rejected); err != nil {
			return err
		}
	}

	if rejected {
		return fmt.Errorf("command rejected by policy engine")
	}

	if name, ok := asString(cmd["command_name"]); ok {
		state.LastCommand = name
	}
	if target, ok := asString(cmd["target"]); ok {
		state.LastTarget = target
	}
	if name, ok := asString(cmd["command_name"]); ok && name == "open_valve" {
		if target, ok := asString(cmd["target"]); ok {
			state.ValveStatus[target] = "open"
		}
	}
	if name, ok := asString(cmd["command_name"]); ok && name == "close_valve" {
		if target, ok := asString(cmd["target"]); ok {
			state.ValveStatus[target] = "closed"
		}
	}
	state.LastUpdateAt = now

	return s.saveState(ctx, state)
}

// 获取设备状态
func (s *SmartContract) GetDeviceState(ctx contractapi.TransactionContextInterface, deviceID string) (*DeviceState, error) {
	return s.getOrInitState(ctx, deviceID)
}

func (s *SmartContract) getOrInitState(ctx contractapi.TransactionContextInterface, deviceID string) (*DeviceState, error) {
	// 根据 ID 查询设备状态
	b, err := ctx.GetStub().GetState("state:" + deviceID)
	if err != nil {
		return nil, err
	}
	// 如果没有状态，创建空状态
	if b == nil {
		return &DeviceState{
			DeviceID:    deviceID,
			LastValues:  map[string]interface{}{},
			ValveStatus: map[string]string{},
		}, nil
	}
	var st DeviceState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	if st.LastValues == nil {
		st.LastValues = map[string]interface{}{}
	}
	if st.ValveStatus == nil {
		st.ValveStatus = map[string]string{}
	}
	return &st, nil
}

func (s *SmartContract) saveState(ctx contractapi.TransactionContextInterface, st *DeviceState) error {
	b, _ := json.Marshal(st)
	return ctx.GetStub().PutState("state:"+st.DeviceID, b)
}

// 对比策略，看是否触发
func (s *SmartContract) evaluatePolicies(
	ctx contractapi.TransactionContextInterface,
	eventType string,
	deviceID string,
	current map[string]interface{},
	state *DeviceState,
) ([]AlertRecord, bool, error) {

	iter, err := ctx.GetStub().GetStateByRange("policy:", "policy;")
	if err != nil {
		return nil, false, err
	}
	defer iter.Close()

	var alerts []AlertRecord
	rejected := false
	now := time.Now().Unix()
	txID := ctx.GetStub().GetTxID()

	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, false, err
		}

		var p Policy
		if err := json.Unmarshal(kv.Value, &p); err != nil {
			return nil, false, err
		}
		if !p.Enabled || p.EventType != eventType {
			continue
		}

		matched, err := matchPolicy(p, current, state)
		if err != nil {
			return nil, false, err
		}
		if !matched {
			continue
		}

		alert := AlertRecord{
			ID:         fmt.Sprintf("%s_%s", txID, p.ID),
			PolicyID:   p.ID,
			PolicyName: p.Name,
			DeviceID:   deviceID,
			EventType:  eventType,
			Severity:   p.Action.Severity,
			Message:    p.Action.Message,
			Payload:    current,
			Timestamp:  now,
			TxID:       txID,
		}

		alertBytes, _ := json.Marshal(alert)
		if err := ctx.GetStub().PutState("alert:"+alert.ID, alertBytes); err != nil {
			return nil, false, err
		}

		alerts = append(alerts, alert)
		if p.Action.Reject {
			rejected = true
		}
	}

	return alerts, rejected, nil
}

func (s *SmartContract) emitAlertBatchEvent(
	ctx contractapi.TransactionContextInterface,
	deviceID string,
	eventType string,
	raw map[string]interface{},
	alerts []AlertRecord,
	rejected bool,
) error {
	ids := make([]string, 0, len(alerts))
	for _, a := range alerts {
		ids = append(ids, a.ID)
	}
	ev := AlertBatchEvent{
		DeviceID:   deviceID,
		EventType:  eventType,
		Timestamp:  time.Now().Unix(),
		HitCount:   len(alerts),
		Rejected:   rejected,
		AlertIDs:   ids,
		Alerts:     alerts,
		RawPayload: raw,
	}
	b, _ := json.Marshal(ev)
	return ctx.GetStub().SetEvent("threat.alert", b)
}

func matchPolicy(p Policy, current map[string]interface{}, state *DeviceState) (bool, error) {
	if len(p.Conditions) == 0 {
		return false, nil
	}

	results := make([]bool, 0, len(p.Conditions))
	for _, c := range p.Conditions {
		left, ok := getFieldValue(c.Source, c.Field, current, state)
		if !ok {
			results = append(results, false)
			continue
		}
		matched, err := compare(left, c.Op, c.Value)
		if err != nil {
			return false, err
		}
		results = append(results, matched)
	}

	logic := strings.ToLower(p.Logic)
	if logic == "" || logic == "all" {
		for _, r := range results {
			if !r {
				return false, nil
			}
		}
		return true, nil
	}
	if logic == "any" {
		for _, r := range results {
			if r {
				return true, nil
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("unsupported policy logic: %s", p.Logic)
}

func getFieldValue(source, field string, current map[string]interface{}, state *DeviceState) (interface{}, bool) {
	switch source {
	case "current":
		v, ok := current[field]
		return v, ok
	case "state":
		if strings.HasPrefix(field, "valve_status.") {
			valve := strings.TrimPrefix(field, "valve_status.")
			v, ok := state.ValveStatus[valve]
			return v, ok
		}
		if field == "last_command" {
			return state.LastCommand, state.LastCommand != ""
		}
		if field == "last_target" {
			return state.LastTarget, state.LastTarget != ""
		}
		v, ok := state.LastValues[field]
		return v, ok
	default:
		return nil, false
	}
}

func compare(left interface{}, op string, right interface{}) (bool, error) {
	switch strings.ToLower(op) {
	case "eq":
		return fmt.Sprintf("%v", left) == fmt.Sprintf("%v", right), nil
	case "ne":
		return fmt.Sprintf("%v", left) != fmt.Sprintf("%v", right), nil
	case "gt", "gte", "lt", "lte":
		lf, err := toFloat64(left)
		if err != nil {
			return false, err
		}
		rf, err := toFloat64(right)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(op) {
		case "gt":
			return lf > rf, nil
		case "gte":
			return lf >= rf, nil
		case "lt":
			return lf < rf, nil
		case "lte":
			return lf <= rf, nil
		}
	}
	return false, fmt.Errorf("unsupported operator: %s", op)
}

func toFloat64(v interface{}) (float64, error) {
	switch t := v.(type) {
	case float64:
		return t, nil
	case float32:
		return float64(t), nil
	case int:
		return float64(t), nil
	case int64:
		return float64(t), nil
	case int32:
		return float64(t), nil
	case json.Number:
		return t.Float64()
	case string:
		return strconv.ParseFloat(t, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}

func asString(v interface{}) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func main() {
	cc, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		panic(err)
	}
	if err := cc.Start(); err != nil {
		panic(err)
	}
}
