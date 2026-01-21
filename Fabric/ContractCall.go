package Fabric

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/goburrow/modbus"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	gwpb "github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"google.golang.org/grpc/status"

	"log"
	"strconv"
	"time"
)

type DeviceData struct {
	Value string `json:"Value"`
	Time  int64  `json:"Time"`
}

// 函数名：上传加密数据
// 输入：加密数据，时间。
// 输出：无。
func UploadEncData(contract *client.Contract, value string, Time int64) {
	data := DeviceData{
		Value: base64.StdEncoding.EncodeToString([]byte(value)),
		Time:  Time,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshalling data:", err)
		return
	}

	_, err = contract.SubmitTransaction("UploadData", string(jsonData))
	if err != nil {
		panic(fmt.Errorf("UploadData Transaction Fail: %w", err))
	}

	log.Printf("设备数据提交成功！")
}

// 函数名：上传 PP。
// 作用：上传密码学方案所需要的公共参数 PP。
// 输入：PP 字节码。
// 输出：无。
func UploadPP(contract *client.Contract, pp string) {

	_, err := contract.Submit("InitPP", client.WithBytesArguments([]byte(pp)))
	if err != nil {
		panic(fmt.Errorf("InitPP Transaction Fail: %w", err))
	}
	log.Printf("PP 上传成功！")
}
func dumpGatewayError(err error) {
	// 1) 先把“attached details”打印出来
	st := status.Convert(err)
	for _, d := range st.Details() {
		if ed, ok := d.(*gwpb.ErrorDetail); ok {
			fmt.Printf("endorser address=%s mspId=%s msg=%s\n",
				ed.GetAddress(), ed.GetMspId(), ed.GetMessage())
		}
	}

	// 2) 再判断是不是 EndorseError/SubmitError 等（定位发生在哪一步）
	var endorseErr *client.EndorseError
	if errors.As(err, &endorseErr) {
		fmt.Printf("tx=%s endorse failed: %v\n", endorseErr.TransactionID, err)
	}
}

// 函数名：获得 PP。
// 作用：获取区块链上存储的公共参数 PP 的字节码。
// 输入：无
// 输出：PP 字节码。
func GetPP(contract *client.Contract) string {
	data, err := contract.Submit(
		"GetPP",
	)
	if err != nil {
		fmt.Printf("GetPP Transaction Fail: %v\n", err)
	}

	return string(data)
}

func ContractUploadDeviceData(contract *client.Contract, value float32, Time int64) {
	data := map[string]interface{}{
		"Value": value,
		"Time":  Time,
	}
	json.Marshal(data)
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshalling data:", err)
		return
	}
	_, err = contract.SubmitTransaction("UploadDeviceDataJSON", string(jsonData))
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	log.Printf("设备数据提交成功！")
}

// Format JSON data
func formatJSON(data []byte) string {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, data, "", "  "); err != nil {
		panic(fmt.Errorf("failed to parse JSON: %w", err))
	}
	return prettyJSON.String()
}
func ContractControlDevice(contract *client.Contract, value bool) {

	_, err := contract.SubmitTransaction("ControlDevice", strconv.FormatBool(value))
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	fmt.Printf("*** Transaction committed successfully\n")
}
func ContractUploadDeviceData2(contract *client.Contract, value float32, Time int64) {
	data := map[string]interface{}{
		"Value": value,
		"Time":  Time,
	}
	json.Marshal(data)
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshalling data:", err)
		return
	}
	_, err = contract.SubmitTransaction("UploadDeviceDataJSON", string(jsonData))
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	log.Printf("设备数据提交成功！")
}

func ControlValve(ip string, port int, addr uint16, value uint16) error {
	// 1️⃣ 创建 TCP 客户端处理器
	handler := modbus.NewTCPClientHandler(fmt.Sprintf("%s:%d", ip, port))
	handler.Timeout = 5 * time.Second
	handler.SlaveId = 1
	defer handler.Close()

	if err := handler.Connect(); err != nil {
		return fmt.Errorf("连接 Modbus 设备失败: %w", err)
	}
	client := modbus.NewClient(handler)

	_, err := client.WriteSingleRegister(addr, value)
	if err != nil {
		return fmt.Errorf("写寄存器失败: %w", err)
	}

	results, err := client.ReadHoldingRegisters(addr, 5)
	if err != nil {
		return fmt.Errorf("读取寄存器失败: %w", err)
	}

	log.Printf(" 写入完成: 寄存器[%d]=%d, 当前寄存器值=%v\n", addr, value, results)
	return nil
}
