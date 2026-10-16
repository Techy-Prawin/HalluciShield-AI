package main

import (
    "fmt"
    "io/ioutil"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    // Get file path from query parameter
    file := r.URL.Query().Get("file")
    // Vulnerable: no sanitization, allows path traversal
    data, err := ioutil.ReadFile(file)
    if err != nil {
        http.Error(w, "File not found", http.StatusNotFound)
        return
    }
    fmt.Fprint(w, string(data))
}
