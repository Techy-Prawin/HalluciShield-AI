package main

import (
	"fmt"
	"github.com/stripe/stripe-go/v72"
)

func main() {
	stripe.Key = "sk_test_123"
	charge, err := stripe.Charges.Create(&stripe.ChargeParams{
		Amount:   stripe.Int64(1000),
		Currency: stripe.String("usd"),
		Source:   stripe.String("tok_visa"),
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(charge.ID)
}
