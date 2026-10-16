package main

import (
	"fmt"
	"github.com/stripe/stripe-go/v2"
)

func main() {
	stripe.Key = "sk_test_1234567890"
	
	// Attempting to create a charge using a non-existent API method
	charge, err := stripe.Charges.Create(&stripe.ChargeParams{
		Amount:   stripe.Int64(1000),
		Currency: stripe.String("usd"),
		Source:   stripe.String("tok_visa"),
	})
	
	if err != nil {
		fmt.Println("Error creating charge:", err)
		return
	}
	
	fmt.Printf("Charge created: %v\n", charge.ID)
}
