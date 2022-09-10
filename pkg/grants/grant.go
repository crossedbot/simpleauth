package grants

import (
	"fmt"
	"strings"
)

// Grant represents an access grant for interacting with the authentication
// service.
type Grant uint32

const (
	// No grants
	GrantUnknown Grant = 0x0000
	GrantNone    Grant = 0x0001

	// OTP grants
	GrantSetOTP      Grant = 0x0002
	GrantOTPValidate Grant = 0x0004
	GrantOTPQR       Grant = 0x0008
	GrantOTP         Grant = 0x0002 | 0x0004 | 0x0008

	// User grants
	GrantUsersRefresh Grant = 0x0100

	// Authenticated grants
	GrantAuthenticated Grant = 0x0002 | 0x0004 | 0x0008 | 0x0100

	// Reserved
	GrantFull Grant = 0xFFFFFFFE
	GrantMax  Grant = 0xFFFFFFFF
)

// GrantStrings map a basic access grant to a string representation.
var GrantStrings = map[Grant]string{
	GrantUnknown:      "unknown",
	GrantNone:         "none",
	GrantSetOTP:       "otp",
	GrantOTPValidate:  "otp-validate",
	GrantOTPQR:        "otp-qr",
	GrantUsersRefresh: "users-refresh",
}

// ToGrant returns an access grant for the given string. The string may be
// comma-separated to include multiple grants; E.g. "otp-validate,otp-qr".
func ToGrant(s string) (Grant, error) {
	var grant Grant
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		found := false
		for k, v := range GrantStrings {
			if strings.EqualFold(p, v) {
				grant |= k
				found = true
				break
			}
		}
		if !found {
			return GrantUnknown, fmt.Errorf("Unknown grant '%s'", p)
		}
	}
	return grant, nil
}

// Clean returns a grant "cleansed" of unused/reserved bits. If the grant
// contains a self-terminating grant (E.g. GrantNone), that is returned instead.
func (g Grant) Clean() Grant {
	if (g & GrantNone) == GrantNone {
		return GrantNone
	}
	return g & GrantAuthenticated
}

// String returns the comma-separated string representation of the access grant.
func (g Grant) String() string {
	var grants []string
	var i uint32 = 0
	for ; i < 32; i++ {
		switch (1 << i) & g {
		case GrantNone:
			grants = append(grants,
				GrantStrings[GrantNone])
		case GrantSetOTP:
			grants = append(grants,
				GrantStrings[GrantSetOTP])
		case GrantOTPValidate:
			grants = append(grants,
				GrantStrings[GrantOTPValidate])
		case GrantOTPQR:
			grants = append(grants,
				GrantStrings[GrantOTPQR])
		case GrantUsersRefresh:
			grants = append(grants,
				GrantStrings[GrantUsersRefresh])
		}
	}
	if len(grants) == 0 {
		return GrantStrings[GrantUnknown]
	}
	return strings.Join(grants, ",")
}
