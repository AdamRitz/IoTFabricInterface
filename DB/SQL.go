package DB

import (
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"time"
)

var MySQL *sql.DB

func InitMySQL() error {
	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:3306)/blockchain?charset=utf8mb4&parseTime=True&loc=Local")
	if err != nil {
		return err
	}

	if err = db.Ping(); err != nil {
		return err
	}

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(time.Hour)

	MySQL = db
	//Logger.Infoln("MySQL 连接成功！")
	return nil
}

// 区块链信息记录函数
//
//	作用：记录区块的高度和交易数量到数据库的 blockdata 表中。
//	调用者：Fabric/Event.go 接收到区块数据就存入 mysql 数据库。
func BlockDataInsert(TxNum uint64, blockNum int) {
	SQL := "INSERT INTO BlockData (BlockNumber,  TxNumber) VALUES (?, ?)"
	_, err := MySQL.Exec(SQL, TxNum, blockNum)
	if err != nil {
		log.Fatal(err)
	}
	//Logger.Infoln("区块数据插入成功！")
}

// 七日交易数据查询函数
//
//	作用：查询最近七天的区块链交易数据。
//	调用者：Web/Web.go 给前端渲染的时候会调用这个函数。
type TxDayStat struct {
	Day      string `json:"day"`
	TotalTxs int64  `json:"total_txs"`
}

func TxNumber7() ([]TxDayStat, error) {
	SQL := `
WITH RECURSIVE days AS (
    SELECT CURDATE() - INTERVAL 6 DAY AS day
    UNION ALL
    SELECT day + INTERVAL 1 DAY
    FROM days
    WHERE day < CURDATE()
)
SELECT 
    DATE_FORMAT(days.day, '%Y-%m-%d') AS day,
    COALESCE(SUM(b.TxNumber), 0) AS total_txs
FROM days
LEFT JOIN blockdata b
    ON b.Time >= days.day
   AND b.Time < days.day + INTERVAL 1 DAY
GROUP BY days.day
ORDER BY days.day;
`

	rows, err := MySQL.Query(SQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []TxDayStat

	for rows.Next() {
		var item TxDayStat
		if err := rows.Scan(&item.Day, &item.TotalTxs); err != nil {
			return nil, err
		}
		result = append(result, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// 区块高度查询
//
//	作用：查询最近当前区块链高度。
//	调用者：Web/Web.go 给前端渲染的时候会调用这个函数。
func QueryChainHeight() (int, error) {
	SQL := "SELECT MAX(BlockNumber) AS block_number FROM blockdata"
	rows, err := MySQL.Query(SQL)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var a int
	if rows.Next() {
		if err := rows.Scan(&a); err != nil {
			return 0, err
		}
	} else {
		return 0, sql.ErrNoRows
	}
	return a, nil
}

type Oracle struct {
	ID          int64     `json:"id"`
	OracleID    string    `json:"oracleId"`
	OracleName  string    `json:"oracleName"`
	OrgName     string    `json:"orgName"`
	PublicKey   string    `json:"publicKey"`
	Endpoint    string    `json:"endpoint"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	DeviceCount int       `json:"deviceCount"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type OracleDevice struct {
	ID              int64     `json:"id"`
	OracleID        string    `json:"oracleId"`
	DeviceID        string    `json:"deviceId"`
	DeviceName      string    `json:"deviceName"`
	DeviceType      string    `json:"deviceType"`
	DevicePublicKey string    `json:"devicePublicKey"`
	DeviceAddress   string    `json:"deviceAddress"`
	Remark          string    `json:"remark"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type AddOracleReq struct {
	OracleName  string `json:"oracleName"`
	OracleID    string `json:"oracleId"`
	OrgName     string `json:"orgName"`
	PublicKey   string `json:"publicKey"`
	Endpoint    string `json:"endpoint"`
	Description string `json:"description"`
}

type AddDeviceReq struct {
	OracleID        string `json:"oracleId"`
	DeviceName      string `json:"deviceName"`
	DeviceID        string `json:"deviceId"`
	DeviceType      string `json:"deviceType"`
	DevicePublicKey string `json:"devicePublicKey"`
	DeviceAddress   string `json:"deviceAddress"`
	Remark          string `json:"remark"`
}

// 函数名：添加预言机
// 作用：添加预言机到区块链，现在是 mysql 实现版本。
// 调用者：Web/Web.go
func AddOracle(req AddOracleReq) error {
	if req.OracleID == "" || req.OracleName == "" || req.OrgName == "" || req.PublicKey == "" || req.Endpoint == "" {
		return errors.New("missing required fields")
	}

	SQL := `
INSERT INTO oracle_info
(oracle_id, oracle_name, org_name, public_key, endpoint, description, status)
VALUES (?, ?, ?, ?, ?, ?, 'online')
`
	_, err := MySQL.Exec(SQL,
		req.OracleID,
		req.OracleName,
		req.OrgName,
		req.PublicKey,
		req.Endpoint,
		req.Description,
	)
	return err
}

// 函数名：查询预言机是否存在
// 作用：查询预言机是否存在。
// 调用者：Web/Web.go
func OracleExists(oracleID string) (bool, error) {
	SQL := `SELECT COUNT(1) FROM oracle_info WHERE oracle_id = ?`
	var cnt int
	err := MySQL.QueryRow(SQL, oracleID).Scan(&cnt)
	if err != nil {
		return false, err
	}
	return cnt > 0, nil
}

// 函数名：添加预言机设备。
// 作用：添加预言机管理的设备
// 调用者：Web/Web.go
func AddOracleDevice(req AddDeviceReq) error {
	if req.OracleID == "" || req.DeviceID == "" || req.DeviceName == "" || req.DeviceType == "" || req.DevicePublicKey == "" || req.DeviceAddress == "" {
		return errors.New("missing required fields")
	}

	exists, err := OracleExists(req.OracleID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("oracle %s not found", req.OracleID)
	}

	SQL := `
INSERT INTO oracle_device
(oracle_id, device_id, device_name, device_type, device_public_key, device_address, remark)
VALUES (?, ?, ?, ?, ?, ?, ?)
`
	_, err = MySQL.Exec(SQL,
		req.OracleID,
		req.DeviceID,
		req.DeviceName,
		req.DeviceType,
		req.DevicePublicKey,
		req.DeviceAddress,
		req.Remark,
	)
	return err
}

// 函数名：预言机列表
// 作用：获取预言机列表，同时统计每个预言机设备数
func ListOracles() ([]Oracle, error) {
	SQL := `
SELECT
    o.id,
    o.oracle_id,
    o.oracle_name,
    o.org_name,
    o.public_key,
    o.endpoint,
    o.description,
    o.status,
    COUNT(d.id) AS device_count,
    o.created_at,
    o.updated_at
FROM oracle_info o
LEFT JOIN oracle_device d
    ON o.oracle_id = d.oracle_id
GROUP BY
    o.id, o.oracle_id, o.oracle_name, o.org_name, o.public_key,
    o.endpoint, o.description, o.status, o.created_at, o.updated_at
ORDER BY o.id DESC
`
	rows, err := MySQL.Query(SQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Oracle
	for rows.Next() {
		var item Oracle
		err := rows.Scan(
			&item.ID,
			&item.OracleID,
			&item.OracleName,
			&item.OrgName,
			&item.PublicKey,
			&item.Endpoint,
			&item.Description,
			&item.Status,
			&item.DeviceCount,
			&item.CreatedAt,
			&item.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		list = append(list, item)
	}

	return list, nil
}

// 函数名：预言机列表统计
// 作用：获取预言机的个数
func OracleNodeCount() (int, error) {
	SQL := `
SELECT COUNT(*)
FROM oracle_info
`
	var count int
	err := MySQL.QueryRow(SQL).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// 统计今日新增总次数，这里先按“今天新增预言机数 + 今天新增设备数”算
func QueryTodayChainCount() (int, error) {
	SQL1 := `SELECT COUNT(1) FROM oracle_info WHERE DATE(created_at) = CURDATE()`
	SQL2 := `SELECT COUNT(1) FROM oracle_device WHERE DATE(created_at) = CURDATE()`

	var a, b int
	if err := MySQL.QueryRow(SQL1).Scan(&a); err != nil {
		return 0, err
	}
	if err := MySQL.QueryRow(SQL2).Scan(&b); err != nil {
		return 0, err
	}
	return a + b, nil
}
