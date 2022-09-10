package models

import (
	"fmt"
	"strings"
)

// UserType represents a user's type.
type UserType int

const (
	// User types
	BaseUserType UserType = iota
	GuestUserType
	AdminUserType
)

// UserTypeStrings is a list of string representations of user types.
var UserTypeStrings = []string{
	"USER",
	"GUEST",
	"ADMIN",
}

// ToUserType returns the UserType for a value user type string. Otherwise an
// error is returned.
func ToUserType(s string) (UserType, error) {
	for i, uts := range UserTypeStrings {
		if strings.EqualFold(s, uts) {
			return UserType(i), nil
		}
	}
	return -1, fmt.Errorf("%s does not match a user type", s)
}

// String returns the string representation of the user type.
func (ut UserType) String() string {
	i := int(ut)
	if i >= 0 && i < len(UserTypeStrings) {
		return UserTypeStrings[i]
	}
	return ""
}
