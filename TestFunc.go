package main

import (
	"fmt"
	"time"
)

func test() {
	ch := make(chan int)

	go func() {
		for {
			time.Sleep(time.Second)
			ch <- 1
		}

	}()
	for {
		select {
		case <-ch:
			fmt.Println("Received data from channel")
		default:
			time.Sleep(time.Millisecond * 10)
		}

	}
}
