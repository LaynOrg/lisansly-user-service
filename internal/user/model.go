package user

const (
	RoleUser = "user"
)

type UserPayload struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type UserDocument struct {
	Id        string `bson:"_id"`
	Email     string `bson:"email"`
	Password  string `bson:"password"`
	Role      string `bson:"role"`
	CreatedAt int64  `bson:"createdAt"`
	DeletedAt int64  `bson:"deletedAt,omitempty"`
}

type RefreshTokenHistoryDocument struct {
	Id        string `bson:"_id"`
	Token     string `bson:"token"`
	ExpiresAt int64  `bson:"expiresAt"`
	UserID    string `bson:"userId"`
}
