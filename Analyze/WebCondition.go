package DataAnalyze

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

// 全局状态集合
var stateSet = NewDeviceStateSet()

// 全局规则列表
var rules = initRules()

// DetectRequest 表示检测接口的请求体
type DetectRequest struct {
	DeviceID string         `json:"deviceId"`
	Current  map[string]any `json:"current"`
}

// DetectResponse 表示检测接口的响应体
type DetectResponse struct {
	Code    int                `json:"code"`
	Message string             `json:"message"`
	Data    []EvaluationResult `json:"data,omitempty"`
}

// StateResponse 表示设备状态查询响应
type StateResponse struct {
	Code    int          `json:"code"`
	Message string       `json:"message"`
	Data    *DeviceState `json:"data,omitempty"`
}

//func main() {
//	r := gin.Default()
//
//	// 健康检查
//	r.GET("/ping", func(c *gin.Context) {
//		c.JSON(http.StatusOK, gin.H{
//			"message": "pong",
//		})
//	})
//
//	// 执行一次检测并更新状态
//	r.POST("/detect", handleDetect)
//
//	// 查询某个设备当前保存的状态
//	r.GET("/state/:deviceId", handleGetState)
//
//	// 查看当前加载的规则
//	r.GET("/rules", handleGetRules)
//
//	r.Run(":8080")
//}

// handleDetect 执行检测
func handleDetect(c *gin.Context) {
	var req DetectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, DetectResponse{
			Code:    400,
			Message: "invalid request body: " + err.Error(),
		})
		return
	}

	results, err := Detect(stateSet, rules, DetectInput{
		DeviceID: req.DeviceID,
		Current:  req.Current,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, DetectResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, DetectResponse{
		Code:    200,
		Message: "detect success",
		Data:    results,
	})
}

// handleGetState 查询设备状态
func handleGetState(c *gin.Context) {
	deviceID := c.Param("deviceId")
	if deviceID == "" {
		c.JSON(http.StatusBadRequest, StateResponse{
			Code:    400,
			Message: "deviceId is empty",
		})
		return
	}

	state, err := GetCurrentState(stateSet, deviceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, StateResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	if state == nil {
		c.JSON(http.StatusOK, StateResponse{
			Code:    200,
			Message: "device state not found",
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusOK, StateResponse{
		Code:    200,
		Message: "success",
		Data:    state,
	})
}

// handleGetRules 查看当前规则
func handleGetRules(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "success",
		"data":    rules,
	})
}

// initRules 初始化规则
func initRules() []RuleSet {
	return []RuleSet{
		{
			ID:          "rule-1",
			Name:        "温度过高",
			Description: "temperature > 80",
			Enabled:     true,
			Priority:    10,
			Root: NewConditionNode(
				BuildSimpleNumberCondition("temperature", OpGt, 80),
			),
		},
		{
			ID:          "rule-2",
			Name:        "温度突变",
			Description: "|current - previous| > 10",
			Enabled:     true,
			Priority:    9,
			Root: NewConditionNode(
				BuildDeltaGtCondition("temperature", 10),
			),
		},
	}
}
