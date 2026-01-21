package Modbus

import (
	"encoding/binary"
	"github.com/goburrow/modbus"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"log"
	"math"
	"time"
)

func PeriodicQueryPLC(contract *client.Contract) {
	ModbusClient, err := ModbusInit()
	if err != nil {
		log.Fatal("Modbus init failed:", err)
	}
	for {
		// for 循环内部累计：每隔 1 秒读取一次 PLC 数据，并把读取到的数据通过 UploadDeviceData 合约上传至区块链。
		t, _ := ModbusClient.ReadHoldingRegisters(5, 2)
		floatVal := math.Float32frombits(binary.BigEndian.Uint32(t))
		// 上传数据 go ContractUploadDeviceData(contract, floatVal, time.Now().Unix()*1000)
		log.Println("Read HoldingRegisters ", floatVal)
		time.Sleep(1 * time.Second)
	}
}
func ModbusInit() (modbus.Client, error) {
	// 创建 Modbus 客户端 handler
	ModbusConnection := modbus.NewTCPClientHandler("192.168.2.1:1000")
	ModbusConnection.Timeout = 10 * time.Second
	ModbusConnection.SlaveId = 1
	if err := ModbusConnection.Connect(); err != nil {
		log.Printf("Modbus连接失败: %v", err)
		return nil, err
	}
	log.Println("Modbus连接成功")

	ModbusClient := modbus.NewClient(ModbusConnection)
	// 返回 handler 和 nil 错误
	return ModbusClient, nil
}
