package DB

import (
	"FabricInterface/Logger"
	"database/sql"
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
	Logger.Infoln("MySQL 连接成功！")
	return nil
}

// 区块链信息记录函数：把从
func BlockDataInsert(TxNum uint64, blockNum int) {
	SQL := "INSERT INTO BlockData (BlockNumber,  TxNumber) VALUES (?, ?)"
	_, err := MySQL.Exec(SQL, TxNum, blockNum)
	if err != nil {
		log.Fatal(err)
	}
	Logger.Infoln("区块数据插入成功！")
}
