package main

import (
	"fmt"
	"os/exec"
)

func main() {
	var userInput string
	fmt.Scanln(&userInput)
	
	// Vulnerable: user input directly in command execution
	cmd := exec.Command("sh", "-c", userInput)
	
	if err := cmd.Run(); err != nil {
		fmt.Println("Error:", err)
	}
}
