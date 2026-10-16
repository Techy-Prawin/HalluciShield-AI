package main

import (
	"fmt"
	"os/exec"
)

func main() {
	var userInput string
	fmt.Scanln(&userInput)
	
	// Vulnerable: directly using user input in command execution
	cmd := exec.Command("sh", "-c", userInput)
	
	if err := cmd.Run(); err != nil {
		fmt.Println("Error:", err)
	}
}
