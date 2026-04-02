package Service

import (
	"FabricInterface/Fabric"
	"FabricInterface/Modbus"
	"log"
	"time"
)

const defaultDeviceID = "dev-002"

func PeriodicQueryPLC() {
	// 同步规则
	if err := Fabric.SynchronizeRule([]string{defaultDeviceID}); err != nil {
		log.Println("规则同步失败:", err)
	} else {
		log.Println("规则同步成功")
	}
	// 执行判断
	for {
		floatVal := Modbus.ReadPLC()
		data := map[string]interface{}{
			"temperature": floatVal,
		}

		record, err := Fabric.Evaluate(defaultDeviceID, data)
		if err != nil {
			log.Println("链下规则执行失败:", err)
			continue
		}

		chainResults := make([]Fabric.RuleResult, 0, len(record.Results))
		for _, r := range record.Results {
			chainResults = append(chainResults, Fabric.RuleResult{
				RuleID:     r.RuleID,
				Expression: r.Expression,
				Match:      r.Match,
				Error:      r.Error,
			})
		}

		chainRecord, err := Fabric.ContractSubmitDeviceData(defaultDeviceID, data, chainResults)
		if err != nil {
			log.Println("数据与规则结果上链失败:", err)
		} else {
			log.Printf("数据与规则结果上链成功: txId=%s resultCount=%d", chainRecord.TxID, len(chainRecord.Results))
		}

		triggered := false
		for _, r := range record.Results {
			if r.Match {
				triggered = true
				log.Printf("规则命中: device=%s rule=%s expr=%s", record.DeviceID, r.RuleID, r.Expression)
			}
		}

		if triggered {
			Modbus.WritePLC()
		}

		log.Println("链下规则执行完成", "PLC温度 VB2008:", floatVal, "ruleCount:", len(record.Results), "triggered:", triggered)
		time.Sleep(1 * time.Second)
	}
}
