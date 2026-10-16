package main

import (
	"fmt"
	"github.com/stripe/stripe-go/v72"
)

func main() {
	stripe.Key = "sk_test_123"
	// Using a non-existent method 'create' on the Charges struct
	charge, err := stripe.Charges.create(stripe.ChargeParams{
		Amount:   stripe.Int64(2000),
		Currency: stripe.String("usd"),
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(charge.ID)
}