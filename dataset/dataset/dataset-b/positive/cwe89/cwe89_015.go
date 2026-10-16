package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	
	db, err := sql.Open("postgres", "user=app password=secret dbname=users sslmode=disable")
	if err != nil {
		http.Error(w, "Database connection failed", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	query := "SELECT name, email FROM users WHERE id = " + id
	
	row := db.QueryRow(query)
	var name, email string
	if err := row.Scan(&name, &email); err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	fmt.Fprintf(w, `{"name": "%s", "email": "%s"}`, name, email)
}

func main() {
	http.HandleFunc("/user", getUserHandler)
	http.ListenAndServe(":8080", nil)
}