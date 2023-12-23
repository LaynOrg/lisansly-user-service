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
	GenerateAccessToken(expirationTime time.Duration, name, email, userId string) (string, error)
	GenerateRefreshToken(expirationTime time.Duration, userId string) (string, error)
	VerifyAccessToken(rawJwtToken string) (*Claims, error)
	VerifyRefreshToken(rawJwtToken string) (*Claims, error)
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
	expirationTime time.Duration,
	name, email, userId string,
) (string, error) {
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(expirationTime)
	claims := Claims{
		Name:  name,
		Email: email,
		Plan:  PlanDefault,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   userId,
			Issuer:    IssuerDefault,
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	return jwtGenerator.generateJwt(claims)
}

func (jwtGenerator *jwtGenerator) GenerateRefreshToken(expirationTime time.Duration, userId string) (string, error) {
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(expirationTime)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    IssuerDefault,
			Subject:   userId,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
		},
	}

	return jwtGenerator.generateJwt(claims)
}

func (jwtGenerator *jwtGenerator) VerifyAccessToken(rawJwtToken string) (*Claims, error) {
	return jwtGenerator.verifyJwt(rawJwtToken, true)
}

func (jwtGenerator *jwtGenerator) VerifyRefreshToken(rawJwtToken string) (*Claims, error) {
	return jwtGenerator.verifyJwt(rawJwtToken, false)
}

func (jwtGenerator *jwtGenerator) generateJwt(claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	signedToken, err := token.SignedString(jwtGenerator.privateKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (jwtGenerator *jwtGenerator) verifyJwt(rawJwtToken string, validateIsTokenStarted bool) (*Claims, error) {
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

	if validateIsTokenStarted {
		isTokenStarted := claims.VerifyNotBefore(now, true)
		if !isTokenStarted {
			return nil, errors.New("jwt token is not started")
		}
	}

	return &claims, nil
}
