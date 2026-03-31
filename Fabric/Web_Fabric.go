package Fabric

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type RuleCreateRequest struct {
	RuleID      string `json:"ruleId" binding:"required"`
	Expression  string `json:"expression" binding:"required"`
	Description string `json:"description"`
}

type RuleBindRequest struct {
	RuleID   string `json:"ruleId" binding:"required"`
	DeviceID string `json:"deviceId" binding:"required"`
}

type SubmitDataRequest struct {
	DeviceID string                 `json:"deviceId" binding:"required"`
	Fields   map[string]interface{} `json:"fields" binding:"required"`
}

const displayTimeLayout = "2006-01-02 15:04:05"

func formatDisplayTime(raw string) string {
	if raw == "" {
		return raw
	}

	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return raw
		}
	}
	return t.Local().Format(displayTimeLayout)
}

func formatRuleForResponse(rule *Rule) gin.H {
	if rule == nil {
		return nil
	}
	return gin.H{
		"ruleId":      rule.RuleID,
		"expression":  rule.Expression,
		"description": rule.Description,
		"updatedTxId": rule.UpdatedTxID,
		"updatedAt":   formatDisplayTime(rule.UpdatedAt),
	}
}

func formatRuleSliceForResponse(rules []Rule) []gin.H {
	out := make([]gin.H, 0, len(rules))
	for _, r := range rules {
		rule := r
		out = append(out, formatRuleForResponse(&rule))
	}
	return out
}

func formatRecordForResponse(record *DataRecord) gin.H {
	if record == nil {
		return nil
	}
	return gin.H{
		"txId":        record.TxID,
		"deviceId":    record.DeviceID,
		"fields":      record.Fields,
		"results":     record.Results,
		"submittedAt": formatDisplayTime(record.SubmittedAt),
	}
}

func RegisterFabricRoutes(rg *gin.RouterGroup) {
	rg.GET("/health", Health)

	rg.POST("/rules", CreateRule)
	rg.GET("/rules", ListAllRules)
	rg.GET("/rules/:ruleId", GetRule)
	rg.GET("/devices/:deviceId/rules", ListRulesForDevice)

	rg.POST("/bindings", BindRuleToDevice)

	rg.POST("/data", SubmitData)
	rg.GET("/data/:txId", GetData)
}

func ensureContractReady(c *gin.Context) bool {
	if contract != nil {
		return true
	}
	c.JSON(http.StatusInternalServerError, gin.H{
		"code": 3,
		"msg":  "fabric contract not initialized",
	})
	return false
}

func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "ok",
	})
}

func CreateRule(c *gin.Context) {
	if !ensureContractReady(c) {
		return
	}

	var req RuleCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 1,
			"msg":  "请求参数错误",
			"err":  err.Error(),
		})
		return
	}

	err := ContractUpsertRule(req.RuleID, req.Expression, req.Description)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 2,
			"msg":  "规则写入失败",
			"err":  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "规则写入成功",
	})
}

func GetRule(c *gin.Context) {
	if !ensureContractReady(c) {
		return
	}

	ruleID := c.Param("ruleId")
	if ruleID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 1,
			"msg":  "ruleId 不能为空",
		})
		return
	}

	rule, err := ContractGetRule(ruleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 2,
			"msg":  "查询规则失败",
			"err":  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "查询成功",
		"data": formatRuleForResponse(rule),
	})
}

func ListAllRules(c *gin.Context) {
	if !ensureContractReady(c) {
		return
	}

	rules, err := ContractListAllRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 2,
			"msg":  "查询全部规则失败",
			"err":  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "查询成功",
		"data": formatRuleSliceForResponse(rules),
	})
}

func ListRulesForDevice(c *gin.Context) {
	if !ensureContractReady(c) {
		return
	}

	deviceID := c.Param("deviceId")
	if deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 1,
			"msg":  "deviceId 不能为空",
		})
		return
	}

	rules, err := ContractListRulesForDevice(deviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 2,
			"msg":  "查询设备规则失败",
			"err":  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "查询成功",
		"data": formatRuleSliceForResponse(rules),
	})
}

func BindRuleToDevice(c *gin.Context) {
	if !ensureContractReady(c) {
		return
	}

	var req RuleBindRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 1,
			"msg":  "请求参数错误",
			"err":  err.Error(),
		})
		return
	}

	err := ContractBindRuleToDevice(req.RuleID, req.DeviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 2,
			"msg":  "绑定规则失败",
			"err":  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "绑定成功",
	})
}

func SubmitData(c *gin.Context) {
	if !ensureContractReady(c) {
		return
	}

	var req SubmitDataRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 1,
			"msg":  "请求参数错误",
			"err":  err.Error(),
		})
		return
	}

	record, err := ContractSubmitDeviceData(req.DeviceID, req.Fields)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 2,
			"msg":  "上传数据失败",
			"err":  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "上传成功",
		"data": formatRecordForResponse(record),
	})
}

func GetData(c *gin.Context) {
	if !ensureContractReady(c) {
		return
	}

	txID := c.Param("txId")
	if txID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 1,
			"msg":  "txId 不能为空",
		})
		return
	}

	record, err := ContractGetData(txID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 2,
			"msg":  "查询数据失败",
			"err":  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "查询成功",
		"data": formatRecordForResponse(record),
	})
}
