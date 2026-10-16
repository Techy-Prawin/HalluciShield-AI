package main

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	content, err := os.ReadFile(filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(content)
}

func main() {
	http.HandleFunc("/read", handler)
	fmt.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
}