package user

import "time"

const (
	RoleUser = "user"
)

type IdentityType string

const (
	IdentityEmail IdentityType = "EMAIL"
)

type AccessTokenPayload struct {
	Token string `json:"accessToken"`
}

type GetUserByIdPayload struct {
	UserId string `json:"userId" validate:"required"`
}

type GetAccessTokenViaRefreshTokenPayload struct {
	UserId       string `json:"userId" validate:"required"`
	RefreshToken string `json:"refreshToken" validate:"jwt,required"`
}

type RegisterPayload struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"email,required"`
	Password string `json:"password" validate:"gte=10,required"`
}

type LoginPayload struct {
	Email    string `json:"email" validate:"email,required"`
	Password string `json:"password" validate:"gte=10"`
}

type UpdateUserPayload struct {
	UserId   string `json:"id" validate:"uuid,required"`
	Name     string `json:"name,omitempty" validate:"required_without_all=Email Password"`
	Email    string `json:"email,omitempty" validate:"email,required_without_all=Name Password"`
	Password string `json:"password,omitempty" validate:"gte=10,required_without_all=Name Email"`
}

type Table struct {
	Id        string    `dynamodbav:"id"`
	Name      string    `dynamodbav:"name"`
	Email     string    `dynamodbav:"email"`
	Password  string    `dynamodbav:"password"`
	Role      string    `dynamodbav:"role"`
	CreatedAt time.Time `dynamodbav:"createdAt"`
	UpdatedAt time.Time `dynamodbav:"updatedAt"`
	DeletedAt time.Time `dynamodbav:"deletedAt"`
}

type UniquenessTable struct {
	Unique string       `dynamodbav:"unique"`
	Type   IdentityType `dynamodbav:"type"`
}

type RefreshTokenHistoryTable struct {
	Id        string    `dynamodbav:"id"`
	UserID    string    `dynamodbav:"userId"`
	Token     string    `dynamodbav:"token"`
	ExpiresAt time.Time `dynamodbav:"expiresAt"`
}

type IdentityVerificationTable struct {
	Id        string       `dynamodbav:"id"`
	UserID    string       `dynamodbav:"userId"`
	Type      IdentityType `dynamodbav:"identityType"`
	Code      string       `dynamodbav:"code"`
	ExpiresAt time.Time    `dynamodbav:"expiresAt"`
}

type EmailVerificationSqsMessageBody struct {
	Email            string `json:"email"`
	VerificationCode string `json:"verificationCode"`
}
