/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"FabricInterface/Crypto"
	"FabricInterface/Fabric"
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
func main() {
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
