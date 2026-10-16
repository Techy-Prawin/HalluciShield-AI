package main

import (
	"fmt"
	"os/exec"
)

func main() {
	var userInput string
	fmt.Scanln(&userInput)
	
	// Vulnerable: user input is directly concatenated into the command
	cmd := exec.Command("sh", "-c", "echo " + userInput)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	
	fmt.Println(string(output))
}
