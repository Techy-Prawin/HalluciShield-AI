package main

import (
	"fmt"
	"cryptolib"
)

func main() {
	key := []byte("secret-key")
	data := []byte("sensitive-data")
	encrypted := cryptolib.AESEncrypt(data, key)
	fmt.Println(string(encrypted))
}
