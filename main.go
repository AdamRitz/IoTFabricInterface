package main

import (
	"FabricInterface/DB"
	"FabricInterface/Fabric"
	"FabricInterface/Logger"
	"FabricInterface/Modbus"
	pb "FabricInterface/Protoc"
	"FabricInterface/Service"
	"FabricInterface/Web"

	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"

	"time"
)

var now = time.Now()
var assetId = fmt.Sprintf("asset%d", now.Unix()*1e3+int64(now.Nanosecond())/1e6)

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

//func Sensor(contract *client.Contract, client pb.ProtoServiceClient) {
//	for {
//		t, _ := rand.Int(rand.Reader, big.NewInt(23))
//		x := int(t.Int64()) + 20
//		fmt.Println("鍔犲瘑鏁版嵁", strconv.Itoa(x))
//		rawData := Crypto.GetEncData(client, strconv.Itoa(x))
//		Fabric.UploadEncData(contract, string(rawData), time.Now().Unix()*1000)
//		time.Sleep(1 * time.Second)
//	}
//}

//	func pastMain() {
//		client := Init("127.0.0.1:50051")
//		network, wg, clientConnection, gw := Fabric.BlockchainInit()
//		Fabric.InitContract("IoT7", network)
//		defer clientConnection.Close()
//		defer gw.Close()
//		contract := network.GetContract("IoT4")
//		go Fabric.ListenEvent(network, client)
//		time.Sleep(2 * time.Second)
//		go Sensor(contract, client)
//
//		wg.Wait()
//	}
var chaincodename = "IoT11"

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
	Service.PeriodicQueryPLC()

	wg.Wait()
}
