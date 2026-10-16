package main

import (
	"fmt"
	"net/http"
)

func main() {
	apiKey := "sk-1234567890abcdef"
	resp, err := http.Get("https://api.example.com/data?key=" + apiKey)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println("Status:", resp.Status)
}
