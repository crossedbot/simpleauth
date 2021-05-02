package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID           primitive.ObjectID `bson:"_id" json:"-"`
	FirstName    string             `bson:"first_name" json:"first_name"`
	LastName     string             `bson:"last_name" json:"last_name"`
	Password     string             `bson:"password" json:"-"`
	Email        string             `bson:"email" json:"email"`
	Phone        string             `bson:"phone" json:"phone"`
	UserType     string             `bson:"user_type" json:"user_type"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time          `bson:"updated_at" json:"updated_at"`
	UserId       string             `bson:"user_id" json:"user_id"`
	Token        string             `bson:"token" json:"-"`
	RefreshToken string             `bson:"refresh_token" json:"-"`
	TotpEnabled  bool               `bson:"totp_enabled" json:"totp_enabled"`
	Totp         string             `bson:"totp" json:"-"`
}

type Users struct {
	Total int    `json:"total_count"`
	Users []User `json:"user_items"`
}

type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Totp struct {
	Enabled bool   `json:"enabled"`
	Otp     string `json:"otp"`
	Qr      []byte `json:"qr"`
}

type AccessToken struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	OtpRequired  bool   `json:"otp_required"`
}
