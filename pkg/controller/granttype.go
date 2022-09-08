package controller

import ()

type GrantType uint32

const (
	GrantTypeUnknown GrantType = iota
	GrantTypeNone
	GrantTypeAuthenticated
	GrantTypeOTP
	GrantTypeSetOTP
	GrantTypeOTPValidate
	GrantTypeOTPQR
	GrantTypeUsersRefresh
)

var GrantTypeStrings = []string{
	"unknown",
	"none",
	"otp,otp-validate,otp-qr,users-refresh",
	"otp,otp-validate,otp-qr",
	"otp",
	"otp-validate",
	"otp-qr",
	"users-refresh",
}

func (g GrantType) String() string {
	if int(g) < len(GrantTypeStrings) {
		return GrantTypeStrings[int(g)]
	}
	return ""
}
