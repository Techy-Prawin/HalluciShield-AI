package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func getUserByID(db *sql.DB, userID string) (string, error) {
	var name string
	query := "SELECT name FROM users WHERE id = '" + userID + "'"
	err := db.QueryRow(query).Scan(&name)
	if err != nil {
		return "", err
	}
	return name, nil
}

func main() {
	db, err := sql.Open("postgres", "user=postgres password=secret dbname=mydb sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	userID := "1; DROP TABLE users;--"
	name, err := getUserByID(db, userID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(name)
}