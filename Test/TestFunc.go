package main

import (
	"FabricInterface/Fabric"
	"encoding/binary"
	"github.com/goburrow/modbus"
	"log"
	"math"
	"time"
)

var client modbus.Client

func ReadPLC() float32 {
	t, _ := client.ReadHoldingRegisters(4, 2)
	floatVal := math.Float32frombits(binary.BigEndian.Uint32(t))
	data := map[string]interface{}{
		"temperature": floatVal,
	}
	Fabric.ContractSubmitDeviceData("dev-001", data)
	return floatVal
}
func WritePLC() {
	_, err := client.WriteSingleRegister(0, 1)
	if err != nil {
		log.Println("写寄存器失败:", err)
	}
}
func PeriodicQueryPLC() {
	for {
		// for 循环内部累计：每隔 1 秒读取一次 PLC 数据
		PLCValue := ReadPLC()
		log.Println("PLC 温度计 VB2008 ： ", PLCValue)
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
func main() {
	client, _ = ModbusInit()

	PeriodicQueryPLC()

}
