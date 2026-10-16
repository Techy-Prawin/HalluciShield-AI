package main

import (
	"fmt"
	"os/exec"
)

func main() {
	var userInput string
	fmt.Scanln(&userInput)
	
	// Vulnerable: user input directly in command
	cmd := exec.Command("sh", "-c", "echo " + userInput)
	output, _ := cmd.CombinedOutput()
	fmt.Println(string(output))
}
