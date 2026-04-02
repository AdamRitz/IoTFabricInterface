package DataAnalyze

import (
	"FabricInterface/DB"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type CreateRuleRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Expression  string   `json:"expression"`
	Priority    int      `json:"priority"`
	Enabled     bool     `json:"enabled"`
	Tags        []string `json:"tags"`
}

type DeleteRuleRequest struct {
	ID string `json:"id"`
}

type ValidateRuleRequest struct {
	Expression string `json:"expression"`
}

func CreateRule(c *gin.Context) {
	var req CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "请求参数格式错误: " + err.Error(),
		})
		return
	}

	req.ID = strings.TrimSpace(req.ID)
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	req.Expression = strings.TrimSpace(req.Expression)

	if req.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "规则 ID 不能为空"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "规则名称不能为空"})
		return
	}
	if req.Expression == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "规则表达式不能为空"})
		return
	}

	rule, err := CreateRuleSetFromExpression(
		req.ID,
		req.Name,
		req.Description,
		req.Expression,
		req.Priority,
		req.Tags,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "创建规则失败: " + err.Error()})
		return
	}
	rule.Enabled = req.Enabled

	if err := DB.UpsertRule(DB.RuleRecord{
		RuleID:      rule.ID,
		Description: rule.Description,
		Expression:  req.Expression,
		UpdatedTxID: "",
		UpdatedAt:   rule.UpdatedAt.Format(time.RFC3339Nano),
	}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "创建规则失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "规则创建成功",
		"data": gin.H{
			"id":          rule.ID,
			"name":        rule.Name,
			"description": rule.Description,
			"expression":  req.Expression,
			"enabled":     rule.Enabled,
			"priority":    rule.Priority,
			"tags":        rule.Tags,
			"createdAt":   rule.CreatedAt,
			"updatedAt":   rule.UpdatedAt,
		},
	})
}

func ListRule(c *gin.Context) {
	records, err := DB.ListRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "查询规则列表失败: " + err.Error()})
		return
	}

	list := make([]gin.H, 0, len(records))
	for _, record := range records {
		list = append(list, gin.H{
			"id":          record.RuleID,
			"name":        record.RuleID,
			"description": record.Description,
			"expression":  record.Expression,
			"enabled":     true,
			"priority":    0,
			"tags":        []string{},
			"updatedAt":   record.UpdatedAt,
		})
	}

	todayCount, err := DB.QueryTodayRuleCount()
	if err != nil {
		todayCount = 0
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     "success",
		"message":    "查询成功",
		"data":       list,
		"todayCount": todayCount,
	})
}

func DeleteRule(c *gin.Context) {
	var req DeleteRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "请求参数格式错误: " + err.Error()})
		return
	}

	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "规则 ID 不能为空"})
		return
	}

	if err := DB.DeleteRuleByID(req.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "删除规则失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "删除成功"})
}

func ValidateRule(c *gin.Context) {
	var req ValidateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "请求参数格式错误: " + err.Error()})
		return
	}

	req.Expression = strings.TrimSpace(req.Expression)
	if req.Expression == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "表达式不能为空"})
		return
	}

	if _, err := ParseRuleExpression(req.Expression); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "表达式不合法: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "表达式校验通过"})
}

func RegisterRuleRoutes(rg *gin.RouterGroup) {
	rg.POST("/create", CreateRule)
	rg.GET("/list", ListRule)
	rg.POST("/delete", DeleteRule)
	rg.POST("/validate", ValidateRule)
}
