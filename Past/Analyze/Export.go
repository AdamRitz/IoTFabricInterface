package DataAnalyze

import (
	"fmt"
)

// DetectInput 表示一次设备检测输入
type DetectInput struct {
	DeviceID string         `json:"deviceId"`
	Current  map[string]any `json:"current"`
}

// Detect 更贴近后续 Fabric 读写流程的版本
// 流程：
// 1. 先拿到 previous
// 2. 同时更新 current
// 3. 用 previous + current 执行规则
func Detect(stateSet *DeviceStateSet, rules []RuleSet, input DetectInput) ([]EvaluationResult, error) {
	if stateSet == nil {
		return nil, fmt.Errorf("stateSet is nil")
	}
	if input.DeviceID == "" {
		return nil, fmt.Errorf("deviceID is empty")
	}
	if input.Current == nil {
		return nil, fmt.Errorf("current data is nil")
	}

	previous, err := stateSet.UpdateAndGetPrevious(input.DeviceID, input.Current)
	if err != nil {
		return nil, err
	}

	results, err := EvaluateRuleSets(rules, input.Current, previous)
	if err != nil {
		return nil, err
	}

	return results, nil
}

// GetCurrentState 查询当前保存的设备状态
func GetCurrentState(stateSet *DeviceStateSet, deviceID string) (*DeviceState, error) {
	if stateSet == nil {
		return nil, fmt.Errorf("stateSet is nil")
	}

	state, exists := stateSet.states[deviceID]
	if !exists {
		return nil, nil
	}

	out := state
	out.LastValues = cloneMap(state.LastValues)
	return &out, nil
}
