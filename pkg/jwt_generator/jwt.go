package jwt_generator

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type JwtGenerator interface {
	GenerateToken(expirationTime time.Time, name, email, userId string) (string, error)
	VerifyToken(rawJwtToken string) (*Claims, error)
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
	name, email, userId string,
) (string, error) {
	issuedAt := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Name:  name,
		Email: email,
		Role:  RoleUser,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   userId,
			Issuer:    IssuerDefault,
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	})

	signedToken, err := token.SignedString(jwtGenerator.secretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (jwtGenerator *jwtGenerator) VerifyToken(rawJwtToken string) (*Claims, error) {
	var claims *Claims

	jwtToken, err := jwt.ParseWithClaims(rawJwtToken, claims, nil)
	if err != nil {
		return nil, err
	}

	if _, ok := jwtToken.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, errors.New("ambiguous jwt token signing method")
	}

	isValidIssuer := claims.VerifyIssuer(IssuerDefault, true)
	if !isValidIssuer {
		return nil, errors.New("ambiguous jwt token issuer")
	}

	now := time.Now().UTC()
	isJwtTokenExpired := claims.VerifyExpiresAt(now, true)
	if !isJwtTokenExpired {
		return nil, errors.New("expired jwt token")
	}

	return claims, nil
}
