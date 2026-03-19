package DB

import "testing"

func TestTxNumber7(t *testing.T) {
	if err := InitMySQL(); err != nil {
		t.Fatal(err)
	}
	data, err := TxNumber7()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range data {
		println(v.Day, v.TotalTxs)
	}
}
