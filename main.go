/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"FabricInterface/Crypto"
	"FabricInterface/Fabric"
	pb "FabricInterface/Protoc" //
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"math/big"
	"strconv"

	"net/http"
	"os"
	"sync"
	"time"
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

//func main1() {
//	network, wg, clientConnection, gw := BlockchainInit()
//	defer clientConnection.Close()
//	defer gw.Close()
//	// Override default values for chaincode and channel name as they may differ in testing contexts.
//
//	contract := network.GetContract("IoTTest5")
//	//ContractUploadDeviceData(contract, 6.6, time.Now().Unix()*1000)
//
//	//ContractUploadDeviceData(contract, 2.2, time.Now().Unix()*1000)
//
//	//ContractUploadDeviceData(contract, 3.2, time.Now().Unix()*1000)
//	go PeriodicQueryPLC(contract)
//	go ListenEvent(network)
//	//IoT(contract)
//	wg.Wait()
//
//}

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

//	func LastMain() {
//		network, _, clientConnection, gw := BlockchainInit()
//		defer clientConnection.Close()
//		defer gw.Close()
//		// Override default values for chaincode and channel name as they may differ in testing contexts.
//
//		contract := network.GetContract("IoTTest5")
//		ContractUploadDeviceData(contract, 6.6, time.Now().Unix()*1000)
//
//		//ContractUploadDeviceData(contract, 2.2, time.Now().Unix()*1000)
//
//		//ContractUploadDeviceData(contract, 3.2, time.Now().Unix()*1000)
//
//		//IoT(contract)
//
//		//getAllAssets(contract)
//		//createAsset(contract)
//		//readAssetByID(contract)
//		//transferAssetAsync(contract)
//		//exampleErrorHandling(contract)
//	}

func Sensor(contract *client.Contract, client pb.ProtoServiceClient) {
	for {
		t, _ := (rand.Int(rand.Reader, big.NewInt(23)))
		x := int(t.Int64()) + 20
		fmt.Println("加密数据", strconv.Itoa(x))
		RawData := Crypto.GetEncData(client, strconv.Itoa(x))
		Fabric.UploadEncData(contract, string(RawData), time.Now().Unix()*1000)
		time.Sleep(1 * time.Second)
	}
}
func main() {
	client := Init("127.0.0.1:50051")
	network, wg, clientConnection, gw := BlockchainInit()
	defer clientConnection.Close()
	defer gw.Close()
	contract := network.GetContract("IoT4")
	go Fabric.ListenEvent(network, client)
	time.Sleep(2 * time.Second)
	go Sensor(contract, client)

	wg.Wait()
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
