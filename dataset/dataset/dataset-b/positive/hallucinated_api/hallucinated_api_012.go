package main

import (
	"fmt"
	"github.com/stripe/stripe-go"
)

func main() {
	stripe.Charges.create("ch_123")
	fmt.Println("Charge created")
}
