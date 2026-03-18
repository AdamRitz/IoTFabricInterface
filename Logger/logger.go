package Logger

import (
	"io"
	"log"
	"os"
)

var Info *log.Logger
var Error *log.Logger

// Logger 初始化函数
func InitLogger() {
	file, err := os.OpenFile("app.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		println(err.Error())
		return
	}

	Writer := io.MultiWriter(os.Stdout, file)
	// [Chain] 记录区块链相关信息，如区块记录，区块链高度等元数据。
	Info = log.New(Writer, "[Info] ", log.Ldate|log.Ltime|log.Lshortfile)
	Error = log.New(Writer, "[ERROR] ", log.Ldate|log.Ltime|log.Lshortfile)

}

// Logger.Info.Println 封装为 Logger.Infoln 降低代码长度
func Infoln(v ...any) {
	Info.Println(v...)
}

func Infof(format string, v ...any) {
	Info.Printf(format, v...)
}

func Errorln(v ...any) {
	Error.Println(v...)
}
