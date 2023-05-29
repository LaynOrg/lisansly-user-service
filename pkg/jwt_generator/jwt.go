package jwt_generator

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type JwtGenerator interface {
	GenerateToken(expirationTime time.Time, email, userId string) (string, error)
}

type jwtGenerator struct {
	secretKey []byte
}

func NewJwtGenerator(secretKey []byte) (JwtGenerator, error) {
	return &jwtGenerator{
		secretKey: secretKey,
	}, nil
}

func (jwtGenerator *jwtGenerator) GenerateToken(
	expirationTime time.Time,
	email, userId string,
) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Email: email,
		Role:  RoleUser,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   userId,
			Issuer:    IssuerDefault,
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	})

	signedToken, err := token.SignedString(jwtGenerator.secretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}
