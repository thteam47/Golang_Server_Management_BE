package global

import "github.com/dgrijalva/jwt-go"

type Claims struct {
	Role string `json:"role"`
	jwt.StandardClaims
}
