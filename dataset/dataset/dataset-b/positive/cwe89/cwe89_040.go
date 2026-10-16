package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func getUserByID(db *sql.DB, id string) (*sql.Rows, error) {
	// Vulnerable: direct string concatenation of user input into SQL query
	query := "SELECT * FROM users WHERE id = '" + id + "'"
	log.Printf("Executing query: %s", query)
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	return rows, nil
}

func main() {
	db, err := sql.Open("postgres", "user=postgres password=secret dbname=mydb sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Simulate user input
	userID := "1 OR 1=1; --"
	rows, err := getUserByID(db, userID)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("User: %d, Name: %s\n", id, name)
	}
}