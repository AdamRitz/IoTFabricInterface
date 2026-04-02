package main

import (
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
)

func main() {
	objectType := "idx~data~time~txId"
	rk := "9223372035089675807"
	txID := "abc123"

	key, err := shim.CreateCompositeKey(objectType, []string{rk, txID})
	if err != nil {
		panic(err)
	}

	fmt.Println("1) 直接打印:")
	fmt.Println(key)

	fmt.Println("\n2) 用 %q 打印，能看见转义后的样子:")
	fmt.Printf("%q\n", key)

	fmt.Println("\n3) 打印字节值:")
	fmt.Printf("%v\n", []byte(key))

}
