package DataAnalyze

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

type RuleHandler struct {
	db *sql.DB
}

func NewRuleHandler(db *sql.DB) *RuleHandler {
	return &RuleHandler{
		db: db,
	}
}

// --------------------------- 请求结构体（BEGIN） ---------------------------

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

// --------------------------- 请求结构体（END） -----------------------------

// CreateRule 创建规则
func (h *RuleHandler) CreateRule(c *gin.Context) {
	var req CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "请求参数格式错误: " + err.Error(),
		})
		return
	}

	if req.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "规则 id 不能为空",
		})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "规则名称不能为空",
		})
		return
	}
	if req.Expression == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "规则表达式不能为空",
		})
		return
	}

	rule, err := CreateAndSaveRuleFromExpression(
		h.db,
		req.ID,
		req.Name,
		req.Description,
		req.Expression,
		req.Priority,
		req.Tags,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "创建规则失败: " + err.Error(),
		})
		return
	}

	// 这里前端展示仍然需要 expression，所以直接回传
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

// ListRule 查询规则列表
func (h *RuleHandler) ListRule(c *gin.Context) {
	rules, err := ListRulesFromMySQL(h.db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "查询规则列表失败: " + err.Error(),
		})
		return
	}

	list := make([]gin.H, 0, len(rules))
	for _, rule := range rules {
		_, expr, err := GetRuleByID(h.db, rule.ID)
		if err != nil {
			expr = ""
		}

		list = append(list, gin.H{
			"id":          rule.ID,
			"name":        rule.Name,
			"description": rule.Description,
			"expression":  expr,
			"enabled":     rule.Enabled,
			"priority":    rule.Priority,
			"tags":        rule.Tags,
			"createdAt":   rule.CreatedAt,
			"updatedAt":   rule.UpdatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     "success",
		"message":    "查询成功",
		"data":       list,
		"todayCount": 0,
	})
}

// DeleteRule 删除规则
func (h *RuleHandler) DeleteRule(c *gin.Context) {
	var req DeleteRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "请求参数格式错误: " + err.Error(),
		})
		return
	}

	if req.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "规则 id 不能为空",
		})
		return
	}

	if err := DeleteRuleByID(h.db, req.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "删除规则失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "删除成功",
	})
}

// ValidateRule 校验规则表达式
func (h *RuleHandler) ValidateRule(c *gin.Context) {
	var req ValidateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "请求参数格式错误: " + err.Error(),
		})
		return
	}

	if req.Expression == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "表达式不能为空",
		})
		return
	}

	_, err := ParseRuleExpression(req.Expression)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "表达式不合法: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "表达式校验通过",
	})
}

// RegisterRuleRoutes 注册规则相关路由
func RegisterRuleRoutes(rg *gin.RouterGroup, db *sql.DB) {
	handler := NewRuleHandler(db)
	rg.POST("/create", handler.CreateRule)
	rg.GET("/list", handler.ListRule)
	rg.POST("/delete", handler.DeleteRule)
	rg.POST("/validate", handler.ValidateRule)
}
