package Fabric

import (
	"fmt"
	"testing"
)

func TestBlockchain(t *testing.T) {
	network, wg, clientConnection, gw := BlockchainInit()
	defer clientConnection.Close()
	defer gw.Close()
	InitContract("IoT7", network)
	rule, err := ContractGetRule("rule-001")
	fmt.Println(rule, err)
	wg.Wait()
}
