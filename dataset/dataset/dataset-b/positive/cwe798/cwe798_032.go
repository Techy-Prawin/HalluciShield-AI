package main

import (
	"fmt"
	"net/http"
)

func main() {
	apiKey := "sk-1234567890abcdef"
	client := &http.Client{}
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	fmt.Println("Status:", resp.Status)
}
