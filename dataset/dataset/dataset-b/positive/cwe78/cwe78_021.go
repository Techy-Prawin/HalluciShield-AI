package main

import (
	"fmt"
	"os/exec"
)

func main() {
	var userInput string
	fmt.Scanln(&userInput)
	cmd := exec.Command("sh", "-c", userInput)
	cmd.Run()
}
