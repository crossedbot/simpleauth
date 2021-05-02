package models

import (
	"fmt"
	"strings"
)

type UserType int

const (
	BaseUserType UserType = iota
	AdminUserType
)

var UserTypeStrings = []string{
	"USER",
	"ADMIN",
}

func (ut UserType) String() string {
	i := int(ut)
	if i >= 0 && i < len(UserTypeStrings) {
		return UserTypeStrings[i]
	}
	return ""
}

func ToUserType(s string) (UserType, error) {
	for i, uts := range UserTypeStrings {
		if strings.EqualFold(s, uts) {
			return UserType(i), nil
		}
	}
	return -1, fmt.Errorf("%s does not match a user type", s)
}
