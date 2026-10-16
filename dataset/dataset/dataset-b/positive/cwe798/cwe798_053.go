package main

import (
	"fmt"
	"net/http"
)

func main() {
	apiKey := "sk-1234567890abcdef"
	resp, err := http.Get("https://api.example.com/data?key=" + apiKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
}