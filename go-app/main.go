package main

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

func main() {
	token := jwt.New(jwt.SigningMethodHS256)
	fmt.Println(token)
}
