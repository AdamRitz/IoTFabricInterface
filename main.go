/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"FabricInterface/Crypto"
	"FabricInterface/DB"
	"FabricInterface/Fabric"
	"FabricInterface/Logger"
	pb "FabricInterface/Protoc" //
	"crypto/rand"
	"fmt"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"math/big"
	"strconv"
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
func pastMain() {
	client := Init("127.0.0.1:50051")
	network, wg, clientConnection, gw := Fabric.BlockchainInit()
	defer clientConnection.Close()
	defer gw.Close()
	contract := network.GetContract("IoT4")
	go Fabric.ListenEvent(network, client)
	time.Sleep(2 * time.Second)
	go Sensor(contract, client)

	wg.Wait()
}
func main() {
	//client := Init("127.0.0.1:50051")
	// 初始化 Logger
	Logger.InitLogger()
	// 初始化区块链
	network, wg, clientConnection, gw := Fabric.BlockchainInit()
	defer clientConnection.Close()
	// 初始化合约
	//contract := network.GetContract("IoT4")
	//go Fabric.ListenEvent(network, client)
	defer gw.Close()
	// 初始化数据库
	DB.InitMySQL()

	go Fabric.ListenBlockEvent(network)
	time.Sleep(2 * time.Second)
	//go Sensor(contract, client)

	wg.Wait()
}
