package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func getUserByID(db *sql.DB, userID string) (string, error) {
	// Vulnerable: Direct string concatenation in SQL query
	query := "SELECT username FROM users WHERE id = '" + userID + "'"
	
	row := db.QueryRow(query)
	var username string
	if err := row.Scan(&username); err != nil {
		return "", err
	}
	return username, nil
}

func main() {
	db, err := sql.Open("postgres", "user=postgres password=secret dbname=mydb sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Simulate user input
	userID := "1 OR 1=1"
	username, err := getUserByID(db, userID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("User:", username)
}