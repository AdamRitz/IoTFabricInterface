package Fabric

import (
	"FabricInterface/Crypto"
	pb "FabricInterface/Protoc"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"google.golang.org/protobuf/proto"
	"log"
)

func ListenEvent(network *client.Network, client pb.ProtoServiceClient) {
	chaincodeName := "IoT4"
	ctx := context.Background()
	events, err := network.ChaincodeEvents(ctx, chaincodeName /*, client.WithStartBlock(0)*/)
	if err != nil {
		log.Fatalf("chaincode events failed: %s", err)
	}
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
			} else if ev.EventName == "Data" {

				fmt.Println("正在解密数据")
				var d DeviceData
				if err := json.Unmarshal(ev.Payload, &d); err != nil {
					log.Fatal("Event JSON decode error:", err)
				}

				var ct pb.CTMessage
				ctRaw, _ := base64.StdEncoding.DecodeString(d.Value)
				if err := proto.Unmarshal(ctRaw, &ct); err != nil {
					log.Fatal("CTMessage UnSerialize Error:", err)
				}
				str := Crypto.GetDecData(client, &ct)
				fmt.Println(string(str))

			}
		case <-ctx.Done():
			log.Println("🛑 上下文取消，退出监听")
			return
		default:

		}

	}

}
