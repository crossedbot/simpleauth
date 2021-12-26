package models

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	MaxNameSize            = 255
	MaxValueSize           = 4096
	MaxEmailLocalPartSize  = 64
	MaxEmailServerPartSize = 255
)

var (
	// Regular expression list
	// Meant to provide a simple syntax check; e.g. good luck validating
	// emails
	UsernameRe     = regexp.MustCompile(`^\w(?:\S?\w){2,127}$`)
	EmailAddressRe = regexp.MustCompile(`^.+@.+\..+$`)
	PhoneRe        = regexp.MustCompile(`^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$`)

	// Errors list
	ErrorInvalidName         = fmt.Errorf("Name exceeds max length of %d", MaxNameSize)
	ErrorInvalidEmailAddress = errors.New("Email address is invalid")
	ErrorInvalidUsername     = errors.New("Username is invalid")
	ErrorInvalidPhonenumber  = errors.New("Phonenumber is invalid")
	ErrorInvalidOptions      = errors.New("Options contain invalid key-value pair")
)

type User struct {
	ID           primitive.ObjectID `bson:"_id" json:"-"`
	FirstName    string             `bson:"first_name" json:"first_name"`
	LastName     string             `bson:"last_name" json:"last_name"`
	Password     string             `bson:"password" json:"-"`
	Email        string             `bson:"email" json:"email"`
	Username     string             `bson:"username" json:"username"`
	Phone        string             `bson:"phone" json:"phone"`
	UserType     string             `bson:"user_type" json:"user_type"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time          `bson:"updated_at" json:"updated_at"`
	UserId       string             `bson:"user_id" json:"user_id"`
	Token        string             `bson:"token" json:"-"`
	RefreshToken string             `bson:"refresh_token" json:"-"`
	TotpEnabled  bool               `bson:"totp_enabled" json:"totp_enabled"`
	Totp         string             `bson:"totp" json:"-"`
	Options      map[string]string  `bson:"options" json:"options"`
}

func (u User) Valid() error {
	if len(u.FirstName) > MaxNameSize {
		return ErrorInvalidName
	}
	if len(u.LastName) > MaxNameSize {
		return ErrorInvalidName
	}
	if len(u.Email) > 0 && !ValidEmailAddress(u.Email) {
		return ErrorInvalidEmailAddress
	}
	if len(u.Username) > 0 && !ValidUsername(u.Username) {
		return ErrorInvalidUsername
	}
	if len(u.Phone) > 0 && !ValidPhonenumber(u.Phone) {
		return ErrorInvalidPhonenumber
	}
	if len(u.Options) > 0 && !ValidOptions(u.Options) {
		return ErrorInvalidOptions
	}
	return nil
}

func ValidUsername(username string) bool {
	return UsernameRe.MatchString(username)
}

func ValidEmailAddress(email string) bool {
	if EmailAddressRe.MatchString(email) {
		idx := strings.LastIndex(email, "@")
		if idx > 0 &&
			len(email[:idx]) <= MaxEmailLocalPartSize &&
			len(email[idx+1:]) <= MaxEmailServerPartSize {
			return true
		}
	}
	return false
}

func ValidPhonenumber(phone string) bool {
	return PhoneRe.MatchString(phone)
}

func ValidOptions(options map[string]string) bool {
	for k, v := range options {
		if len(k) > MaxNameSize || len(v) > MaxValueSize {
			return false
		}
	}
	return true
}

type Users struct {
	Total int    `json:"total_count"`
	Users []User `json:"user_items"`
}

type Login struct {
	Name     string `json:"name"`
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
