package Crypto

import (
	pb "FabricInterface/Protoc"
	"context"
	"encoding/hex"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"log"
	"time"
)

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
func GetEncData(client pb.ProtoServiceClient, a string) []byte {
	in := &pb.DataMessage{Data: []byte(a)}
	var ct *pb.CTMessage
	{
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ct, _ = client.EncData(ctx, in)
		raw, _ := proto.Marshal(ct)
		return raw
	}
}
func GetDecData(client pb.ProtoServiceClient, ct *pb.CTMessage) string {

	{
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		out, err := client.DecData(ctx, ct)
		if err != nil {
			log.Fatalf("GetDecData: %v", err)
		}

		return string(out.Data)
	}
}
func TestEnc(client pb.ProtoServiceClient) {
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
			log.Fatalf("GetUSK: %v", err)
			return
		}
		log.Println("Key Get Success!")

		// 3) SetUSK
		{
			ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel2()

			_, err = client.SetUSK(ctx2, uskMsg)
			if err != nil {
				log.Fatalf("SetUSK: %v", err)
				return
			}
			log.Println("SetKey Success!")
		}
	}
	var b *pb.CTMessage
	for {
		a := ""

		fmt.Scanln(&a)
		if a == "Enc" {
			message := ""
			fmt.Scanln(&message)
			in := &pb.DataMessage{Data: []byte(message)}
			var ct *pb.CTMessage
			{
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				ct, _ = client.EncData(ctx, in)
				raw, _ := proto.Marshal(ct)
				b = ct
				fmt.Println(hex.EncodeToString(raw))
			}
		} else if a == "Dec" {

			{
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				out, _ := client.DecData(ctx, b)
				fmt.Printf("%s\n", string(out.GetData()))

			}
		} else if a == "getpp" {
			{
				t := pb.EmptyMessage{}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				client.GetPP(ctx, &t)
				fmt.Printf("%s\n", 123)

			}
		}
	}
}
