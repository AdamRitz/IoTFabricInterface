package DataAnalyze

import (
	"fmt"
	"testing"
)

func TestAnalyze(t *testing.T) {
	a := "Luowenbin"
	expression, err := tokenizeRuleExpression(a)
	if err != nil {
		return
	}
	for index, tt := range expression {
		fmt.Println(index)
		fmt.Println(tt.typ)
	}
}
