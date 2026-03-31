package Web

import (
	DataAnalyze "FabricInterface/Analyze"
	"FabricInterface/DB"
	"FabricInterface/Fabric"
	"database/sql"
	"errors"
	"github.com/go-sql-driver/mysql"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func InitWeb() {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://127.0.0.1:5173"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	ruleGroup := r.Group("/rule")
	DataAnalyze.RegisterRuleRoutes(ruleGroup)

	fabricGroup := r.Group("/fabric")
	Fabric.RegisterFabricRoutes(fabricGroup)

	r.GET("/GetTxNumber7", GetTxNumber7)
	r.GET("/GetChainHeight", GetChainHeight)

	r.POST("/oracle/add", AddOracle)
	r.GET("/oracle/list", ListOracles)
	r.POST("/oracle/device/add", AddOracleDevice)
	r.GET("/oracle/GetOracleNodeCount", GetOracleNodeCount)

	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}

func GetTxNumber7(c *gin.Context) {
	data, err := DB.TxNumber7()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 500,
			"msg":  "query failed",
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, data)
}
func GetOracleNodeCount(c *gin.Context) {
	count, err := DB.OracleNodeCount()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 500,
			"msg":  "query failed",
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "success",
		"data": count,
	})
}
func GetChainHeight(c *gin.Context) {
	data, err := DB.QueryChainHeight()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 500,
			"msg":  "query failed",
			"data": nil,
		})
		return
	}
	c.JSON(http.StatusOK, data)
}

type OracleListResp struct {
	Code       int         `json:"code"`
	Msg        string      `json:"msg"`
	Data       interface{} `json:"data"`
	ChainCount int         `json:"chainCount"`
}

func AddOracle(c *gin.Context) {
	var req DB.AddOracleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "invalid request body",
		})
		return
	}

	req.OracleID = strings.TrimSpace(req.OracleID)
	req.OracleName = strings.TrimSpace(req.OracleName)
	req.OrgName = strings.TrimSpace(req.OrgName)
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	req.Endpoint = strings.TrimSpace(req.Endpoint)
	req.Description = strings.TrimSpace(req.Description)

	if req.OracleID == "" || req.OracleName == "" || req.OrgName == "" || req.PublicKey == "" || req.Endpoint == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "missing required fields",
		})
		return
	}

	err := DB.AddOracle(req)
	if err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			c.JSON(http.StatusBadRequest, gin.H{
				"status":  "error",
				"message": "oracleId already exists",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":      "success",
		"message":     "棰勮█鏈烘坊鍔犳垚鍔?",
		"txId":        "centralized-oracle-" + req.OracleID,
		"blockNumber": 0,
	})
}

func ListOracles(c *gin.Context) {
	data, err := DB.ListOracles()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 500,
			"msg":  "query failed",
			"data": nil,
		})
		return
	}

	chainCount, err := DB.QueryTodayChainCount()
	if err != nil {
		chainCount = 0
	}

	c.JSON(http.StatusOK, OracleListResp{
		Code:       200,
		Msg:        "success",
		Data:       data,
		ChainCount: chainCount,
	})
}

func AddOracleDevice(c *gin.Context) {
	var req DB.AddDeviceReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "invalid request body",
		})
		return
	}

	req.OracleID = strings.TrimSpace(req.OracleID)
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.DeviceName = strings.TrimSpace(req.DeviceName)
	req.DeviceType = strings.TrimSpace(req.DeviceType)
	req.DevicePublicKey = strings.TrimSpace(req.DevicePublicKey)
	req.DeviceAddress = strings.TrimSpace(req.DeviceAddress)
	req.Remark = strings.TrimSpace(req.Remark)

	if req.OracleID == "" || req.DeviceID == "" || req.DeviceName == "" || req.DeviceType == "" || req.DevicePublicKey == "" || req.DeviceAddress == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "missing required fields",
		})
		return
	}

	err := DB.AddOracleDevice(req)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusBadRequest, gin.H{
				"status":  "error",
				"message": "oracle not found",
			})
			return
		}

		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			c.JSON(http.StatusBadRequest, gin.H{
				"status":  "error",
				"message": "device already exists under this oracle",
			})
			return
		}

		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusBadRequest, gin.H{
				"status":  "error",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":      "success",
		"message":     "璁惧娣诲姞鎴愬姛",
		"txId":        "centralized-device-" + req.DeviceID,
		"blockNumber": 0,
	})
}
