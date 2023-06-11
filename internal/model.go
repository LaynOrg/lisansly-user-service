package user

import "time"

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
	Name     string `json:"name,omitempty" validate:"required_without_all=Email Password|gt=0"`
	Email    string `json:"email,omitempty" validate:"required_without_all=Name Password|email"`
	Password string `json:"password,omitempty" validate:"required_without_all=Name Email|gte=10"`
}

type Document struct {
	Id        string    `bson:"_id"`
	Name      string    `json:"name"`
	Email     string    `bson:"email"`
	Password  string    `bson:"password"`
	Role      string    `bson:"role"`
	CreatedAt time.Time `bson:"createdAt,omitempty"`
	UpdatedAt time.Time `bson:"updatedAt,omitempty"`
	DeletedAt time.Time `bson:"deletedAt,omitempty"`
}

type RefreshTokenHistoryDocument struct {
	Id        string    `bson:"_id"`
	UserID    string    `bson:"userId"`
	Token     string    `bson:"token"`
	ExpiresAt time.Time `bson:"expiresAt"`
}
