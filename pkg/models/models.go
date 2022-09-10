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
	// Validation constants
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

// User models a user in the authentication service.
type User struct {
	ID           primitive.ObjectID `bson:"_id" json:"-"`
	FirstName    string             `bson:"first_name" json:"first_name"`
	LastName     string             `bson:"last_name" json:"last_name"`
	Password     string             `bson:"password" json:"password"`
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

// Valid returns nil when the user is valid, otherwise an error is returned.
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

// ValidUsername returns true if the given username is valid.
func ValidUsername(username string) bool {
	return UsernameRe.MatchString(username)
}

// ValidEmailAddress return true if the given email address is valid.
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

// ValidPhonenumber returns true if the given phonenumber is valid.
func ValidPhonenumber(phone string) bool {
	return PhoneRe.MatchString(phone)
}

// ValidOptions returns true if the map options are valid.
func ValidOptions(options map[string]string) bool {
	for k, v := range options {
		if len(k) > MaxNameSize || len(v) > MaxValueSize {
			return false
		}
	}
	return true
}

// Users represents a list of users.
type Users struct {
	Total int    `json:"total_count"`
	Users []User `json:"user_items"`
}

// Login represents a login request.
type Login struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// Totp represents a timed-based OTP.
type Totp struct {
	Enabled bool   `json:"enabled"`
	Otp     string `json:"otp"`
	Qr      []byte `json:"qr"`
}

// AccessToken represents an access and refresh tokens.
type AccessToken struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	OtpRequired  bool   `json:"otp_required"`
}
