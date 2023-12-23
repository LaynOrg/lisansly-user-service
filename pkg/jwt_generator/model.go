package jwt_generator

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	IssuerDefault = "lisansly"
	PlanDefault   = "free"

	AccessTokenExpirationDuration          = 5 * time.Minute
	RefreshTokenExpirationDuration         = 24 * time.Hour
	IdentityVerificationExpirationDuration = 3 * time.Hour
)

type Claims struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Plan  string `json:"role"`
	jwt.RegisteredClaims
}

type Tokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}
