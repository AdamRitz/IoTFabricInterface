package Service

import (
	"FabricInterface/Fabric"
	"FabricInterface/Modbus"
	"log"
	"time"
)

func PeriodicQueryPLC() {
	for {
		// for 循环内部累计：每隔 1 秒读取一次 PLC 数据
		floatVal := Modbus.ReadPLC()
		data := map[string]interface{}{
			"temperature": floatVal,
		}
		// 数据上链
		_, err := Fabric.ContractSubmitDeviceData("dev-002", data)
		if err != nil {
			log.Println("数据上传失败")
		}
		log.Println("数据上传成功 ", "PLC 温度计 VB2008 ： ", floatVal)
		time.Sleep(1 * time.Second)
	}
}
