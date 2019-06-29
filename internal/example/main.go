package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/delfosim/cognito/token"
)

func main() {
	var (
		awsRegion        = os.Getenv("AWS_REGION")
		awsCognitoPoolID = os.Getenv("AWS_COGNITO_POOL_ID")
	)

	tokenString := "<token here>"

	auth, err := token.NewAuth(awsRegion, awsCognitoPoolID)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	result, err := auth.Validate(tokenString)
	if err != nil {
		log.Println("RESULT", err)
		os.Exit(1)
	}

	jsonString, err := json.Marshal(result)
	if err != nil {
		log.Println("JSON", err)
		os.Exit(1)
	}

	log.Println(string(jsonString))
}
