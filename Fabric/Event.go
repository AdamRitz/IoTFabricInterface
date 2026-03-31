package Fabric

import (
	"FabricInterface/DB"
	"FabricInterface/Logger"
	"FabricInterface/Modbus"
	"context"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"log"
	"time"
)

func ListenContractEvent(network *client.Network, chaincodeName string) {
	ctx := context.Background()
	events, err := network.ChaincodeEvents(ctx, chaincodeName /*, client.WithStartBlock(0)*/)
	if err != nil {
		log.Fatalf("chaincode events failed: %s", err)
	}
	Logger.Infof("📡 事件监听已启动：chaincode=%s\n", chaincodeName)
	// for select 并行等待数据
	for {
		select {
		case ev, ok := <-events:
			Logger.Infof(" 事件: name=%s tx=%s block=%d", ev.EventName, ev.TransactionID, ev.BlockNumber)
			if !ok {
				Logger.Infoln("✅ 事件通道已关闭，退出监听")
				return
			} else if ev == nil {
				Logger.Infoln(" 收到 nil 事件，忽略")
				continue
			} else if ev.EventName == "dev-001" {
				println("dev-001 Event Received")
			} else if ev.EventName == "dev-002" {
				println("dev-002 Event Received", string(ev.Payload))
				Modbus.WritePLC()
			}
			//} else if ev.EventName == "Data" {
			//
			//	Logger.Infoln("正在解密数据")
			//	var d DeviceData
			//	if err := json.Unmarshal(ev.Payload, &d); err != nil {
			//		log.Fatal("Event JSON decode error:", err)
			//	}
			//
			//	var ct pb.CTMessage
			//	ctRaw, _ := base64.StdEncoding.DecodeString(d.Value)
			//	if err := proto.Unmarshal(ctRaw, &ct); err != nil {
			//		log.Fatal("CTMessage UnSerialize Error:", err)
			//	}
			//	str := Crypto.GetDecData(client, &ct)
			//	data, _ := strconv.ParseFloat(str, 32)
			//	ThingsBoard.SendToThingsBoard(float32(data), d.Time)
			//	fmt.Println(string(str), d.Time)
			//
			//}
		case <-ctx.Done():
			Logger.Infoln("🛑 上下文取消，退出监听")
			return
		default:

		}

	}

}

//func ListenContractEvent(network *client.Network, client pb.ProtoServiceClient) {
//	chaincodeName := "IoT4"
//	ctx := context.Background()
//	events, err := network.ChaincodeEvents(ctx, chaincodeName /*, client.WithStartBlock(0)*/)
//	if err != nil {
//		log.Fatalf("chaincode events failed: %s", err)
//	}
//	Logger.Infoln("📡 事件监听已启动：chaincode=%s\n", chaincodeName)
//	// for select 并行等待数据
//	for {
//		select {
//		case ev, ok := <-events:
//			Logger.Infoln(" 事件: name=%s tx=%s block=%d", ev.EventName, ev.TransactionID, ev.BlockNumber)
//			if !ok {
//				Logger.Infoln("✅ 事件通道已关闭，退出监听")
//				return
//			} else if ev == nil {
//				Logger.Infoln(" 收到 nil 事件，忽略")
//				continue
//			}
//			//} else if ev.EventName == "Data" {
//			//
//			//	Logger.Infoln("正在解密数据")
//			//	var d DeviceData
//			//	if err := json.Unmarshal(ev.Payload, &d); err != nil {
//			//		log.Fatal("Event JSON decode error:", err)
//			//	}
//			//
//			//	var ct pb.CTMessage
//			//	ctRaw, _ := base64.StdEncoding.DecodeString(d.Value)
//			//	if err := proto.Unmarshal(ctRaw, &ct); err != nil {
//			//		log.Fatal("CTMessage UnSerialize Error:", err)
//			//	}
//			//	str := Crypto.GetDecData(client, &ct)
//			//	data, _ := strconv.ParseFloat(str, 32)
//			//	ThingsBoard.SendToThingsBoard(float32(data), d.Time)
//			//	fmt.Println(string(str), d.Time)
//			//
//			//}
//		case <-ctx.Done():
//			Logger.Infoln("🛑 上下文取消，退出监听")
//			return
//		default:
//
//		}
//
//	}
//
//}

type BlockStat struct {
	BlockchainID string
	BlockNumber  uint64
	BlockTime    time.Time
	TxCount      int
}

func ListenBlockEvent(network *client.Network) {
	ctx := context.Background()

	events, err := network.BlockEvents(ctx /*, client.WithStartBlock(0)*/)
	if err != nil {
		log.Fatalf("block events failed: %s", err)
	}

	Logger.Infoln("📡 区块事件监听已启动")

	for {
		select {
		case ev, ok := <-events:
			if !ok {
				Logger.Infoln("✅ 区块事件通道已关闭，退出监听")
				return
			}
			if ev == nil {
				Logger.Infoln("⚠️ 收到 nil 区块事件，忽略")
				continue
			}
			blockNumber := ev.GetHeader().GetNumber()
			txCount := len(ev.GetData().GetData())
			Logger.Infof("Block Number: %d, txCount: %d, Time: %s", blockNumber, txCount, time.Now().Format("2006-01-02 15:04:05"))
			DB.BlockDataInsert(blockNumber, txCount)
			//println("BlockNumber", ev.GetHeader().GetNumber())
			//println("PreviousHash", fmt.Sprintf("%x", ev.GetHeader().GetPreviousHash()))
			//println("BlockHash")
			//println("txCount", len(ev.GetData().GetData()))

			// 这里后面可以直接写 MySQL
			// SaveBlockStat(db, info)

		case <-ctx.Done():
			log.Println("🛑 上下文取消，退出区块监听")
			return
		}
	}
}

//func ParseBlockEvent(ev *common.Block, blockchainID string) BlockStat {
//	var blockTime time.Time
//	txCount := 0
//
//	if ev.GetData() != nil {
//		txCount = len(ev.GetData().GetData())
//	}
//
//	// 这里先不给时间强依赖，避免不同版本字段不一致时直接报错
//	// 如果你的 ev.Metadata 里能拿到时间，再补进去
//	if ev.GetMetadata() != nil && ev.GetMetadata().GetTimestamp() != nil {
//		blockTime = ev.GetMetadata().GetTimestamp().AsTime()
//	}
//
//	return BlockStat{
//		BlockchainID: blockchainID,
//		BlockNumber:  ev.GetHeader().GetNumber(),
//		BlockTime:    blockTime,
//		TxCount:      txCount,
//	}
//}
