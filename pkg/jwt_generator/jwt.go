package jwt_generator

import (
	"crypto/ecdsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"

	"user-service/pkg/config"
)

type JwtGenerator interface {
	GenerateAccessToken(expirationTime time.Time, name, email, userId string) (string, error)
	GenerateRefreshToken(expirationTime time.Time, userId string) (string, error)
	VerifyAccessToken(rawJwtToken string) (*Claims, error)
}

type jwtGenerator struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

func NewJwtGenerator(jwtConfig *config.JwtConfig) (JwtGenerator, error) {
	parsedEC256PrivateKey, err := jwt.ParseECPrivateKeyFromPEM(jwtConfig.PrivateKey)
	if err != nil {
		return nil, err
	}

	parsedEC256PublicKey, err := jwt.ParseECPublicKeyFromPEM(jwtConfig.PublicKey)
	if err != nil {
		return nil, err
	}

	return &jwtGenerator{
		privateKey: parsedEC256PrivateKey,
		publicKey:  parsedEC256PublicKey,
	}, nil
}

func (jwtGenerator *jwtGenerator) GenerateAccessToken(
	expirationTime time.Time,
	name, email, userId string,
) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		Name:  name,
		Email: email,
		Role:  PlanDefault,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   userId,
			Issuer:    IssuerDefault,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	signedToken, err := token.SignedString(jwtGenerator.privateKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (jwtGenerator *jwtGenerator) GenerateRefreshToken(expirationTime time.Time, userId string) (string, error) {
	now := time.Now().UTC()
	claims := jwt.RegisteredClaims{
		ID:        uuid.New().String(),
		Issuer:    IssuerDefault,
		Subject:   userId,
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	signedToken, err := token.SignedString(jwtGenerator.privateKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (jwtGenerator *jwtGenerator) VerifyAccessToken(rawJwtToken string) (*Claims, error) {
	var (
		err    error
		claims Claims
	)

	_, err = jwt.ParseWithClaims(rawJwtToken, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, errors.New("jwt token is not valid signature")
		}

		return jwtGenerator.publicKey, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil {
		return nil, err
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

	isTokenStarted := claims.VerifyNotBefore(now, true)
	if !isTokenStarted {
		return nil, errors.New("jwt token is not started")
	}

	return &claims, nil
}
