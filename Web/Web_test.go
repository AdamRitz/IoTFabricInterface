package Web

import "testing"
import "FabricInterface/DB"

func TestGetTxNumber7(t *testing.T) {
	if err := DB.InitMySQL(); err != nil {
		t.Fatal(err)
	}
	InitWeb()
}
