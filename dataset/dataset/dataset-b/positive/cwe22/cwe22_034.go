package main

import (
	"fmt"
	"os"
)

func main() {
	var filename string
	fmt.Scanln(&filename)
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()
	fmt.Println("File opened successfully")
}
