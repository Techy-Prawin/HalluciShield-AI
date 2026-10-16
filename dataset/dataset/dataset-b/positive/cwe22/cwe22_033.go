package main

import (
	"fmt"
	"os"
)

func main() {
	var filename string
	fmt.Scanln(&filename)
	data, err := os.ReadFile("/data/" + filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(data))
}