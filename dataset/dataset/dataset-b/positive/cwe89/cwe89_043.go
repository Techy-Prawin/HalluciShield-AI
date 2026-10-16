package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

var db *sql.DB

func init() {
	var err error
	db, err = sql.Open("postgres", "user=postgres password=secret dbname=mydb sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := "SELECT name, email FROM users WHERE id = '" + id + "'"
	row := db.QueryRow(query)
	var name, email string
	if err := row.Scan(&name, &email); err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "Name: %s, Email: %s", name, email)
}

func main() {
	http.HandleFunc("/user", getUserHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}