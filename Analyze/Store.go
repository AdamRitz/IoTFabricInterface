package DataAnalyze

import (
	"time"
)

// DeviceState 表示某个设备最近一次保存的状态
type DeviceState struct {
	DeviceID   string         `json:"deviceId"`
	LastValues map[string]any `json:"lastValues"`
	UpdatedAt  time.Time      `json:"updatedAt"`
}

// DeviceStateSet 是当前调试阶段的中心化内存实现
// 注意：这个版本不加锁，只适合单线程或你明确接受暂时不考虑并发的场景
type DeviceStateSet struct {
	states map[string]DeviceState
}

// NewDeviceStateSet 创建一个内存状态仓储
func NewDeviceStateSet() *DeviceStateSet {
	return &DeviceStateSet{
		states: make(map[string]DeviceState),
	}
}

// ----------------------------------------------------------- DeviceStateSet 结构体方法 （BEGIN）--------------------------------------------------------------------------
// cloneMap 浅拷贝一份 map，避免外部后续修改影响内部状态
func cloneMap(src map[string]any) map[string]any {
	if src == nil {
		return map[string]any{}
	}

	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// GetPrevious 获取某设备上一份状态
func (r *DeviceStateSet) GetPrevious(deviceID string) (map[string]any, bool, error) {
	state, ok := r.states[deviceID]
	if !ok {
		return nil, false, nil
	}
	return cloneMap(state.LastValues), true, nil
}

// SaveCurrent 保存当前状态
func (r *DeviceStateSet) SaveCurrent(deviceID string, current map[string]any) error {
	r.states[deviceID] = DeviceState{
		DeviceID:   deviceID,
		LastValues: cloneMap(current),
		UpdatedAt:  time.Now(),
	}
	return nil
}

// UpdateAndGetPrevious 先取旧值，再保存新值
func (r *DeviceStateSet) UpdateAndGetPrevious(deviceID string, current map[string]any) (map[string]any, error) {
	var previous map[string]any

	if state, ok := r.states[deviceID]; ok {
		previous = cloneMap(state.LastValues)
	}

	r.states[deviceID] = DeviceState{
		DeviceID:   deviceID,
		LastValues: cloneMap(current),
		UpdatedAt:  time.Now(),
	}

	return previous, nil
}

// ----------------------------------------------------------- DeviceStateSet 结构体方法 （END）--------------------------------------------------------------------------
// 使用结构体方法的好处是
// （1）不用每次重复传同一批参数
// （2）绑定对象
