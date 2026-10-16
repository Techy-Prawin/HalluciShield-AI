package main

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	data, err := os.ReadFile(filename)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func main() {
	http.HandleFunc("/read", handler)
	fmt.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
}