package main

import (
	"fmt"
	"log"

	auth "github.com/Torkel-Aannestad/Argon2-Go-Guide/internal"
)

func main() {

	plaintextPassword := "SecretPassword"
	secretKey := []byte("passphrasewhichneedstobe32bytes!")

	encryptedHash, err := auth.GenerateFromPassword(plaintextPassword, secretKey, auth.DefaultParams)
	if err != nil {
		log.Fatal(err)
	}

	passwordUsedInLoginForm := "Differentpassword"
	match, err := auth.ComparePasswordAndHash(passwordUsedInLoginForm, encryptedHash, secretKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Match: %v\n", match)
}
