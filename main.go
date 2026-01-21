/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/goburrow/modbus"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	pb "FabricInterface/Protoc" //
)

const (
	mspID        = "Org1MSP"
	certPath     = "./User1@org1.example.com-cert.pem"
	keyPath      = "./priv_sk"
	tlsCertPath  = "./ca.crt"
	peerEndpoint = "192.168.88.131:7051"
	gatewayPeer  = "peer0.org1.example.com"
)

var now = time.Now()
var assetId = fmt.Sprintf("asset%d", now.Unix()*1e3+int64(now.Nanosecond())/1e6)

func main1() {
	network, wg, clientConnection, gw := BlockchainInit()
	defer clientConnection.Close()
	defer gw.Close()
	// Override default values for chaincode and channel name as they may differ in testing contexts.

	contract := network.GetContract("IoTTest5")
	//ContractUploadDeviceData(contract, 6.6, time.Now().Unix()*1000)

	//ContractUploadDeviceData(contract, 2.2, time.Now().Unix()*1000)

	//ContractUploadDeviceData(contract, 3.2, time.Now().Unix()*1000)
	go PeriodicQueryPLC(contract)
	go ListenEvent(network)
	//IoT(contract)
	wg.Wait()

}
func TestAll(addr string) error {
	// 1) dial
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	client := pb.NewProtoServiceClient(conn)

	// 2) GetUSK
	attributeVec := []bool{true, false, false, true, false}
	attrMsg := &pb.AttributeMessage{}
	for _, b := range attributeVec {
		attrMsg.Attribute = append(attrMsg.Attribute, b)
	}

	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		uskMsg, err := client.GetUSK(ctx, attrMsg)
		if err != nil {
			return fmt.Errorf("GetUSK: %w", err)
		}
		log.Println("Key Get Success!")

		// 3) SetUSK
		{
			ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel2()

			_, err = client.SetUSK(ctx2, uskMsg)
			if err != nil {
				return fmt.Errorf("SetUSK: %w", err)
			}
			log.Println("SetKey Success!")
		}
	}

	// 4) EncData
	in := &pb.DataMessage{Data: []byte(makeString('A', 256))}
	var ct *pb.CTMessage
	var tEnc time.Duration

	{
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		t1 := time.Now()
		ct, err = client.EncData(ctx, in)
		tEnc = time.Since(t1)
		if err != nil {
			return fmt.Errorf("EncData: %w", err)
		}
	}

	// 5) DecData
	var out *pb.DataMessage
	var tDec time.Duration

	{
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		t1 := time.Now()
		out, err = client.DecData(ctx, ct)
		tDec = time.Since(t1)
		if err != nil {
			return fmt.Errorf("DecData: %w", err)
		}
	}

	fmt.Printf("Enc(ms)=%d\n", tEnc.Milliseconds())
	fmt.Printf("Enc+Dec(ms)=%d\n", (tEnc + tDec).Milliseconds())
	fmt.Printf("%s\n", string(out.GetData()))
	return nil
}

// 生成 length 个同样字符的 string
func makeString(ch byte, length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = ch
	}
	return string(b)
}
func Test() {
	if err := TestAll("127.0.0.1:50051"); err != nil {
		log.Fatal(err)
	}
}
func Init(addr string) pb.ProtoServiceClient {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
		return nil
	}
	client := pb.NewProtoServiceClient(conn)
	return client
}
func LastMain() {
	network, _, clientConnection, gw := BlockchainInit()
	defer clientConnection.Close()
	defer gw.Close()
	// Override default values for chaincode and channel name as they may differ in testing contexts.

	contract := network.GetContract("IoTTest5")
	ContractUploadDeviceData(contract, 6.6, time.Now().Unix()*1000)

	//ContractUploadDeviceData(contract, 2.2, time.Now().Unix()*1000)

	//ContractUploadDeviceData(contract, 3.2, time.Now().Unix()*1000)

	//IoT(contract)

	//getAllAssets(contract)
	//createAsset(contract)
	//readAssetByID(contract)
	//transferAssetAsync(contract)
	//exampleErrorHandling(contract)
}
func main() {

}
func BlockchainInit() (*client.Network, sync.WaitGroup, *grpc.ClientConn, *client.Gateway) {
	var wg sync.WaitGroup

	// 启动异步事件监听
	wg.Add(1) // 增加等待组计数
	// The gRPC client connection should be shared by all Gateway connections to this endpoint
	clientConnection := newGrpcConnection()

	id := newIdentity()
	sign := newSign()

	// Create a Gateway connection for a specific client identity
	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(clientConnection),
		// Default timeouts for different gRPC calls
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		panic(err)
	}

	// Override default values for chaincode and channel name as they may differ in testing contexts.

	channelName := "mychannel"
	network := gw.GetNetwork(channelName)
	log.Printf("Fabric 网络已连接")
	return network, wg, clientConnection, gw
}

func PeriodicQueryPLC(contract *client.Contract) {
	ModbusClient, err := ModbusInit()
	if err != nil {
		log.Fatal("Modbus init failed:", err)
	}
	for {
		// for 循环内部累计：每隔 1 秒读取一次 PLC 数据，并把读取到的数据通过 UploadDeviceData 合约上传至区块链。
		t, _ := ModbusClient.ReadHoldingRegisters(5, 2)
		floatVal := math.Float32frombits(binary.BigEndian.Uint32(t))
		go ContractUploadDeviceData(contract, floatVal, time.Now().Unix()*1000)
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
func SendToThingsBoard(floatVal float32, timestamp int64) {
	data := map[string]interface{}{
		"ts": timestamp,
		"values": map[string]interface{}{
			"temperature": floatVal,
		},
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest("POST", "http://192.168.88.129:8080/api/v1/5nUpzAxKz1qXCGSBu4lT/telemetry", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
}

// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection() *grpc.ClientConn {
	certificatePEM, err := os.ReadFile(tlsCertPath)
	if err != nil {
		panic(fmt.Errorf("failed to read TLS certifcate file: %w", err))
	}

	certificate, err := identity.CertificateFromPEM(certificatePEM)
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

	connection, err := grpc.NewClient(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}

	return connection
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func newIdentity() *identity.X509Identity {
	certificatePEM, err := os.ReadFile(certPath)
	if err != nil {
		panic(fmt.Errorf("failed to read certificate file: %w", err))
	}

	certificate, err := identity.CertificateFromPEM(certificatePEM)
	if err != nil {
		panic(err)
	}

	id, err := identity.NewX509Identity(mspID, certificate)
	if err != nil {
		panic(err)
	}

	return id
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign() identity.Sign {
	privateKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}

	return sign
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
func ListenEvent(network *client.Network) {

	chaincodeName := "IoTTest5" // 你的链码名；如果只是测试，也可以用 "basic"
	ctx := context.Background()
	events, _ := network.ChaincodeEvents(ctx, chaincodeName /*, client.WithStartBlock(0)*/)
	log.Printf("📡 事件监听已启动：chaincode=%s\n", chaincodeName)
	// for select 并行等待数据
	for {
		select {
		case ev, ok := <-events:
			log.Printf(" 事件: name=%s tx=%s block=%d", ev.EventName, ev.TransactionID, ev.BlockNumber)
			if !ok {
				log.Println("✅ 事件通道已关闭，退出监听")
				return
			} else if ev == nil {
				log.Println(" 收到 nil 事件，忽略")
				continue
			} else if ev.EventName == "CommandEvent" {

				var DecodeedJSON map[string]interface{}
				err := json.Unmarshal(ev.Payload, &DecodeedJSON)
				if err != nil {
					log.Printf("payload(raw): %s\n", string(ev.Payload))
					return
				}
				cmd, ok := DecodeedJSON["Command"].(bool)
				if ok {
					if cmd == true {
						go func() {
							if err := ControlValve("192.168.2.1", 1000, 0, 1); err != nil {
								log.Printf(" Modbus 控制失败: %v", err)
							}
						}()
					} else if cmd == false {
						go func() {
							if err := ControlValve("192.168.2.1", 1000, 0, 0); err != nil {
								log.Printf(" Modbus 控制失败: %v", err)
							}
						}()
					}

				} else {
					log.Println("⚠️ 没有找到 cmd 字段或不是字符串")
				}

			} else if ev.EventName == "UploadDeviceDataEvent" {
				log.Println("⚠️ 已接收 UploadDeviceDataEvent 事件")
				var DecodeedJSON map[string]interface{}
				err := json.Unmarshal(ev.Payload, &DecodeedJSON)
				fmt.Println(DecodeedJSON)
				if err != nil {
					log.Printf("payload(raw): %s\n", string(ev.Payload))
					return
				}
				data, ok1 := DecodeedJSON["Value"]
				time, ok2 := DecodeedJSON["Time"]
				if ok1 && ok2 {
					data1 := data.(float64)
					time1 := time.(float64)
					SendToThingsBoard(float32(data1), int64(time1))
				} else {
					if !ok1 {
						log.Printf("没有对应字段1")
					}
					if !ok2 {
						log.Println("没有对应字段2")
					}

				}

			} else {
				continue
			}

		case <-ctx.Done():
			log.Println("🛑 上下文取消，退出监听")
			return
		default:

		}

	}

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
