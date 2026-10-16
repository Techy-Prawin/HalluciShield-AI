package main

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("user")
		pwd := r.FormValue("pwd")
		if user == "admin" && pwd == "password123" {
			w.WriteHeader(200)
			fmt.Fprintln(w, "Access Granted")
		} else {
			w.WriteHeader(401)
			fmt.Fprintln(w, "Access Denied")
		}
	})
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Starting server on port %s\n", port)
	http.ListenAndServe(":"+port, nil)
}
