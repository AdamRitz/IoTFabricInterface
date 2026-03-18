package Fabric

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type ChainStatRequest struct {
	BlockchainID string    `json:"blockchain_id"`
	Time         time.Time `json:"time"`
	TxCount      int64     `json:"tx_count"`
}

type Response struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

func chainStatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(Response{
			Code: 405,
			Msg:  "only POST is allowed",
		})
		return
	}

	var req ChainStatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(Response{
			Code: 400,
			Msg:  "invalid json: " + err.Error(),
		})
		return
	}

	if req.BlockchainID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(Response{
			Code: 400,
			Msg:  "blockchain_id is required",
		})
		return
	}

	log.Printf("received: blockchain_id=%s, time=%s, tx_count=%d\n",
		req.BlockchainID,
		req.Time.Format("2006-01-02 15:04:05"),
		req.TxCount,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(Response{
		Code: 200,
		Msg:  "success",
	})
}

func main() {
	http.HandleFunc("/chain/stat", chainStatHandler)

	addr := ":8080"
	log.Println("server listening on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
