package ThingsBoard

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

func SendToThingsBoard(floatVal float32, timestamp int64) {
	data := map[string]interface{}{
		"ts": timestamp,
		"values": map[string]interface{}{
			"temperature": floatVal,
		},
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest("POST", "http://192.168.88.129:8080/api/v1/5nUpzAxKz1qXCGSBu4lT/telemetry", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
}
