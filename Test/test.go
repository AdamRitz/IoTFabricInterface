package main

import (
	"fmt"

	"github.com/expr-lang/expr"
)

func main() {
	env := map[string]any{
		"temp":      45,
		"valveOpen": true,
	}

	code := `temp > 40 && valveOpen == true`

	program, err := expr.Compile(code, expr.Env(env))
	if err != nil {
		panic(err)
	}

	output, err := expr.Run(program, env)
	if err != nil {
		panic(err)
	}
	output, err = expr.Run(program, map[string]any{
		"valveOpen": true,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(output) // true
}
