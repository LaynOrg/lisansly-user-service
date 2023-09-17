package user

import "time"

const (
	UniquenessEmail = "EMAIL"
)

const (
	RoleUser = "user"
)

type AccessTokenPayload struct {
	Token string `json:"accessToken"`
}

type GetUserByIdPayload struct {
	UserId string `json:"userId" validate:"required"`
}

type GetAccessTokenViaRefreshTokenPayload struct {
	UserId       string `json:"userId" validate:"required"`
	RefreshToken string `json:"refreshToken" validate:"required,jwt"`
}

type RegisterPayload struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=10"`
}

type LoginPayload struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"gte=10"`
}

type UpdateUserPayload struct {
	UserId   string `json:"userId" validate:"required,uuid"`
	Name     string `json:"name,omitempty" validate:"required_without_all=Email Password"`
	Email    string `json:"email,omitempty" validate:"required_without_all=Name Password,email"`
	Password string `json:"password,omitempty" validate:"required_without_all=Name Email,gte=10"`
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
	Unique string `dynamodbav:"unique"`
	Type   string `dynamodbav:"type"`
}

type RefreshTokenHistoryTable struct {
	Id        string    `dynamodbav:"id"`
	UserID    string    `dynamodbav:"userId"`
	Token     string    `dynamodbav:"token"`
	ExpiresAt time.Time `dynamodbav:"expiresAt"`
}
