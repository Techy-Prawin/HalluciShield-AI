package main

import (
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/", handler)
    http.ListenAndServe(":8080", nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
    userInput := r.URL.Query().Get("msg")
    // Vulnerable: directly inject user input into HTML without escaping
    fmt.Fprintf(w, "<html><body><h1>Message</h1><p>%s</p></body></html>", userInput)
}
