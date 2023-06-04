package user

const (
	RoleUser = "user"
)

type UserRegisterPayload struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,len=10"`
}

type UserLoginPayload struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserDocument struct {
	Id        string `bson:"_id"`
	Name      string `json:"name"`
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
