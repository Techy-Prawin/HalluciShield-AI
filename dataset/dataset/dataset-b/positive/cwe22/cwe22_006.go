package main

import (
	"fmt"
	"os"
)

func main() {
	var filename string
	fmt.Scanln(&filename)
	content, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	fmt.Println(string(content))
}