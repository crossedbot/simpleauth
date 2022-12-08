package models

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gorm.io/gorm"
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
	ID           uint           `gorm:"primarykey" json:"-"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
	FirstName    string         `json:"first_name"`
	LastName     string         `json:"last_name"`
	Password     string         `json:"password"`
	Email        string         `json:"email"`
	Username     string         `json:"username"`
	Phone        string         `json:"phone"`
	UserType     string         `json:"user_type"`
	UserId       string         `json:"user_id"`
	Token        string         `json:"-"`
	RefreshToken string         `json:"-"`
	TotpEnabled  bool           `json:"totp_enabled"`
	Totp         string         `json:"-"`
	Options      Options        `gorm:"serializer:json" json:"options"`
	PublicKey    string         `json:"public_key"`
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

// ValidOptions returns true if the options map is valid.
func ValidOptions(options Options) bool {
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
