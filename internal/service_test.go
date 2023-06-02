//go:build unit

package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"user-api/pkg/jwt_generator"
)

var TestPrivateKey = []byte(`
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
dn/RsYEONbwQSjIfMPkvxF+8HQ==
-----END PRIVATE KEY-----`)

var TestPublicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`)

const (
	TestUserId            = "abcd-abcd-abcd-abcd-abcd"
	TestUserName          = "Lynicis"
	TestEmail             = "test@test.com"
	TestPassword          = "12345"
	TestEncryptedPassword = "$2a$10$aoVeJWgCZe6sueOO3wEIQOoZA3DbolyP6aTTMgmcbsmC3MojKdFme\n"

	TestRefreshTokenHistoryDocumentId = "abcd-abcd-abcd-abcd"
)

func TestNewService(t *testing.T) {
	userService := NewService(nil, nil)

	assert.Implements(t, (*Service)(nil), userService)
}

func TestService_Register(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(TestUserId, nil)

		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(nil)

		jwtGenerator, err := jwt_generator.NewJwtGenerator([]byte("secret-key"))
		require.NoError(t, err)

		userService := NewService(mockUserRepository, jwtGenerator)
		tokens, err := userService.Register(ctx, &UserRegisterPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NoError(t, err)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
	})

	t.Run("when error occurred while insert user should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(
				"",
				errors.New("something went wrong"),
			)

		userService := NewService(mockUserRepository, nil)
		_, err := userService.Register(ctx, &UserRegisterPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while generate access token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)

		mockUserRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(TestUserId, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateToken(gomock.Any(), TestEmail, TestUserId).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockUserRepository, mockJwtGenerator)
		_, err := userService.Register(ctx, &UserRegisterPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while generate refresh token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)

		mockUserRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(TestUserId, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateToken(gomock.Any(), TestEmail, TestUserId).
			Return(TestAccessToken, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateToken(gomock.Any(), TestEmail, TestUserId).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockUserRepository, mockJwtGenerator)
		_, err := userService.Register(ctx, &UserRegisterPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while insert refresh token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			InsertUser(ctx, gomock.Any()).
			Return(TestUserId, nil)

		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(errors.New("something went wrong"))

		jwtGenerator, err := jwt_generator.NewJwtGenerator([]byte("secret-key"))
		require.NoError(t, err)

		userService := NewService(mockUserRepository, jwtGenerator)
		_, err = userService.Register(ctx, &UserRegisterPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})
}

func TestService_Login(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&UserDocument{
				Id:       TestUserId,
				Email:    TestEmail,
				Password: TestEncryptedPassword,
				Role:     RoleUser,
			}, nil)

		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(nil)

		jwtGenerator, err := jwt_generator.NewJwtGenerator([]byte("secret-key"))
		require.NoError(t, err)

		userService := NewService(mockUserRepository, jwtGenerator)
		tokens, err := userService.Login(ctx, &UserLoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.NoError(t, err)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
	})

	t.Run("when error occurred while find user should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(nil, errors.New("something went wrong"))

		userService := NewService(mockUserRepository, nil)
		_, err := userService.Login(ctx, &UserLoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while compare password should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&UserDocument{
				Id:       TestUserId,
				Email:    TestEmail,
				Password: "",
				Role:     RoleUser,
			}, nil)

		userService := NewService(mockUserRepository, nil)
		_, err := userService.Login(ctx, &UserLoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while generate access token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)

		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&UserDocument{
				Id:       TestUserId,
				Email:    TestEmail,
				Password: TestEncryptedPassword,
				Role:     RoleUser,
			}, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateToken(gomock.Any(), TestEmail, TestUserId).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockUserRepository, mockJwtGenerator)
		_, err := userService.Login(ctx, &UserLoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while generate access token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)

		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&UserDocument{
				Id:       TestUserId,
				Email:    TestEmail,
				Password: TestEncryptedPassword,
				Role:     RoleUser,
			}, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateToken(gomock.Any(), TestEmail, TestUserId).
			Return(TestAccessToken, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateToken(gomock.Any(), TestEmail, TestUserId).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockUserRepository, mockJwtGenerator)
		_, err := userService.Login(ctx, &UserLoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})

	t.Run("when error occurred while insert user should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.
			EXPECT().
			FindUserWithEmail(ctx, TestEmail).
			Return(&UserDocument{
				Id:       TestUserId,
				Email:    TestEmail,
				Password: TestEncryptedPassword,
				Role:     RoleUser,
			}, nil)

		mockUserRepository.
			EXPECT().
			InsertRefreshTokenHistory(ctx, gomock.Any()).
			Return(errors.New("something went wrong"))

		jwtGenerator, err := jwt_generator.NewJwtGenerator([]byte("secret-key"))
		require.NoError(t, err)

		userService := NewService(mockUserRepository, jwtGenerator)
		_, err = userService.Login(ctx, &UserLoginPayload{
			Email:    TestEmail,
			Password: TestPassword,
		})

		assert.Error(t, err)
	})
}

func TestService_GetAccessToken(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryDocument{
				Id:        TestRefreshTokenHistoryDocumentId,
				Token:     TestRefreshToken,
				ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Unix(),
				UserID:    TestUserId,
			}, nil)

		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(&UserDocument{
				Id:        TestUserId,
				Email:     TestEmail,
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC().Unix(),
			}, nil)

		jwtGenerator, err := jwt_generator.NewJwtGenerator([]byte("secret"))
		require.NoError(t, err)

		userService := NewService(mockUserRepository, jwtGenerator)
		accessToken, err := userService.GetAccessToken(ctx, TestUserId, TestRefreshToken)

		assert.NoError(t, err)
		assert.NotEmpty(t, accessToken)
	})

	t.Run("when error occurred while find refresh token with user id should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(nil, errors.New("something went wrong"))

		userService := NewService(mockUserRepository, nil)
		accessToken, err := userService.GetAccessToken(ctx, TestUserId, TestRefreshToken)

		assert.Error(t, err)
		assert.Empty(t, accessToken)
	})

	t.Run("if refresh token its not same should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryDocument{
				Id:        TestRefreshTokenHistoryDocumentId,
				Token:     "wrong-refresh-token",
				ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Unix(),
				UserID:    TestUserId,
			}, nil)

		userService := NewService(mockUserRepository, nil)
		accessToken, err := userService.GetAccessToken(ctx, TestUserId, TestRefreshToken)

		assert.Error(t, err)
		assert.Empty(t, accessToken)
	})

	t.Run("if refresh token expires should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryDocument{
				Id:        TestRefreshTokenHistoryDocumentId,
				Token:     TestRefreshToken,
				ExpiresAt: 0,
				UserID:    TestUserId,
			}, nil)

		userService := NewService(mockUserRepository, nil)
		accessToken, err := userService.GetAccessToken(ctx, TestUserId, TestRefreshToken)

		assert.Error(t, err)
		assert.Empty(t, accessToken)
	})

	t.Run("when error occurred while find user with id should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryDocument{
				Id:        TestRefreshTokenHistoryDocumentId,
				Token:     TestRefreshToken,
				ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Unix(),
				UserID:    TestUserId,
			}, nil)

		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(nil, errors.New("something went wrong"))

		userService := NewService(mockUserRepository, nil)
		accessToken, err := userService.GetAccessToken(ctx, TestUserId, TestRefreshToken)

		assert.Error(t, err)
		assert.Empty(t, accessToken)
	})

	t.Run("when error occurred generate access token should return error", func(t *testing.T) {
		ctx := context.Background()
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)

		mockUserRepository.
			EXPECT().
			FindRefreshTokenWithUserId(ctx, TestUserId).
			Return(&RefreshTokenHistoryDocument{
				Id:        TestRefreshTokenHistoryDocumentId,
				Token:     TestRefreshToken,
				ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Unix(),
				UserID:    TestUserId,
			}, nil)

		mockUserRepository.
			EXPECT().
			FindUserWithId(ctx, TestUserId).
			Return(&UserDocument{
				Id:        TestUserId,
				Email:     TestEmail,
				Password:  TestPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC().Unix(),
			}, nil)

		mockJwtGenerator.
			EXPECT().
			GenerateToken(gomock.Any(), TestEmail, TestUserId).
			Return("", errors.New("something went wrong"))

		userService := NewService(mockUserRepository, mockJwtGenerator)
		accessToken, err := userService.GetAccessToken(ctx, TestUserId, TestRefreshToken)

		assert.Error(t, err)
		assert.Empty(t, accessToken)
	})
}
