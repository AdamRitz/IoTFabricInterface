package main

import "encoding/json"

type TestStruct struct {
	DeviceID string `json:"deviceID"`
	Data     string `json:"data"`
}

func main() {
	a := TestStruct{"ID", "Datas"}
	// json.Marshal：输入为结构体，普通变量等内容。输出为编码好的 JSON bytes。报错原因可能是输入的类型不支持转为 JSON。
	j, _ := json.Marshal(a)
	// 要输出 JSON 字符串需要先转为 String
	println(string(j))
	var b TestStruct

	// json.Unmarshal，输入为 json 的 bytes。输出为目标结构体。报错原因可能是转化失败。
	json.Unmarshal(j, &b)
	println(b.DeviceID)

}
