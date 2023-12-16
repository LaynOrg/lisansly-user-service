package user

import "time"

const (
	PlanDefault = "free"
)

type IdentityType string

const (
	IdentityEmail IdentityType = "EMAIL"
)

type AccessTokenPayload struct {
	Token string `json:"accessToken"`
}

type GetUserByIdPayload struct {
	Id string `json:"userId" validate:"required,uuid"`
}

type GetAccessTokenViaRefreshTokenPayload struct {
	UserId       string `json:"userId" validate:"required,uuid"`
	RefreshToken string `json:"refreshToken" validate:"required,jwt"`
}

type RegisterPayload struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=10"`
}

type LoginPayload struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=10"`
}

type UpdateUserPayload struct {
	Id       string `json:"id" validate:"required,uuid"`
	Name     string `json:"name,omitempty" validate:"required_without_all=Email Password,omitempty"`
	Email    string `json:"email,omitempty" validate:"required_without_all=Name Password,omitempty,email"`
	Password string `json:"password,omitempty" validate:"required_without_all=Name Email,omitempty,gte=10"`
}

type Table struct {
	Id        string    `dynamodbav:"id"`
	Name      string    `dynamodbav:"name"`
	Email     string    `dynamodbav:"email"`
	Password  string    `dynamodbav:"password"`
	Plan      string    `dynamodbav:"plan"`
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
