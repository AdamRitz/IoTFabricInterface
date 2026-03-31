package main

import (
	"encoding/json"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"log"
)

type SmartContract struct {
	contractapi.Contract
}

func (s *SmartContract) UploadDeviceDataJSON(ctx contractapi.TransactionContextInterface, Data string) error {
	ctx.GetStub().SetEvent("UploadDeviceDataEvent", []byte(Data))
	return nil
}
func (s *SmartContract) ControlDevice(ctx contractapi.TransactionContextInterface, command bool) error {
	data := map[string]interface{}{
		"Command": command,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	ctx.GetStub().SetEvent("CommandEvent", jsonData)
	return nil
}
func (s *SmartContract) TestTime(ctx contractapi.TransactionContextInterface, Time int64) error {
	data := map[string]interface{}{
		"Time": Time,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	ctx.GetStub().SetEvent("TestTimeEvent", jsonData)
	return nil
}
func main() {
	cc, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating SmartContract chaincode: %v", err)
	}
	if err := cc.Start(); err != nil {
		log.Panicf("Error starting SmartContract chaincode: %v", err)
	}
}
