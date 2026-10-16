package main

import (
	"os/exec"
	"fmt"
)

func main() {
	userInput := "malicious_input"
	cmd := exec.Command("sh", "-c", "echo " + userInput)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(string(output))
}
