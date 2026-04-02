package main

import (
	"FabricInterface/DB"
	"FabricInterface/Fabric"
	"FabricInterface/Logger"
	"FabricInterface/Modbus"
	"FabricInterface/Web"
	"log"

	"time"
)

var chaincodename = "IoT17"

func main() {
	// 初始化日志
	Logger.InitLogger()

	// 初始化区块链
	network, wg, clientConnection, gw := Fabric.BlockchainInit()
	Fabric.InitContract(chaincodename, network)

	defer clientConnection.Close()
	defer gw.Close()

	// 初始化数据库
	if err := DB.InitMySQL(); err != nil {
		log.Fatalf("InitMySQL failed: %v", err)
	}
	// 初始化网页
	go Web.InitWeb()
	// 初始化区块链数据接受收
	//go Fabric.ListenBlockEvent(network)
	go Fabric.ListenContractEvent(network, chaincodename)

	// 初始化 Modbus 和 物联网预言机
	Modbus.ModbusInit()
	time.Sleep(2 * time.Second)
	// 开启 PLC数据上链服务
	//Service.PeriodicQueryPLC()

	wg.Wait()
}
