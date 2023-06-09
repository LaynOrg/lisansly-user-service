package user

import "time"

const (
	RoleUser = "user"
)

type RegisterPayload struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=10"`
}

type LoginPayload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Document struct {
	Id        string    `bson:"_id"`
	Name      string    `json:"name"`
	Email     string    `bson:"email"`
	Password  string    `bson:"password"`
	Role      string    `bson:"role"`
	CreatedAt time.Time `bson:"createdAt"`
	DeletedAt time.Time `bson:"deletedAt,omitempty"`
}

type RefreshTokenHistoryDocument struct {
	Id        string    `bson:"_id"`
	Token     string    `bson:"token"`
	ExpiresAt time.Time `bson:"expiresAt"`
	UserID    string    `bson:"userId"`
}
