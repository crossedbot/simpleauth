package grants

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	middleware "github.com/crossedbot/simplemiddleware"
)

var (
	// Errors
	ErrRequestGrant = errors.New("Request does not match grant")
)

// Grant represents an access grant for interacting with the authentication
// service.
type Grant uint32

const (
	GrantDelimiter  = ","
	MaxCustomGrants = 8 // bits

	// Grant Sections
	GrantSectionOTP      Grant = 0x000000FE
	GrantSectionUsers    Grant = 0x0000FF00
	GrantSectionCustom   Grant = 0x00FF0000
	GrantSectionReserved Grant = 0xFF000000

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

	// Short names
	GrantOTP:           "otp-all",
	GrantAuthenticated: "authenticated",
}

// ToGrant returns an access grant for the given string. The string may be
// comma-separated to include multiple grants; E.g. "otp-validate,otp-qr".
func ToGrant(s string) (Grant, error) {
	var grant Grant
	parts := strings.Split(s, GrantDelimiter)
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

// ContainsGrant return nil if the given request's context contains the given
// access grant. Otherwise an error is returned.
func ContainsGrant(grant Grant, r *http.Request) error {
	reqGrantStr, ok := r.Context().Value(middleware.ClaimGrant).(string)
	if !ok {
		return middleware.ErrGrantDataType
	}
	reqGrant, err := ToGrant(reqGrantStr)
	if err != nil {
		return err
	}
	if (reqGrant & grant) != grant {
		return ErrRequestGrant
	}
	return nil
}

// GetCustomGrant returns the custom user grants currently set. Passing grant
// names will limit the result to those grants.
func GetCustomGrant(grant ...string) Grant {
	var grants Grant
	limit := len(grant) > 0
	for k, v := range GrantStrings {
		if k&GrantSectionCustom > 0 {
			if limit {
				for _, g := range grant {
					if strings.EqualFold(v, g) {
						grants |= k
					}
				}
			} else {
				grants |= k
			}
		}
	}
	return grants
}

// IsCustomGrantsSet is a conveniance function that returns true if custom user
// grants are set.
func IsCustomGrantsSet() bool {
	return (GetCustomGrant() & GrantSectionCustom) != GrantUnknown
}

// SetCustomGrants sets additional user grants. The number of grants are limited
// by MaxCustomGrants. Using this function will remove any existing custom
// grants.
func SetCustomGrants(grants []string) error {
	var v Grant
	if len(grants) > MaxCustomGrants {
		return fmt.Errorf("%d exceeds max allowable length of %d\n",
			len(grants), MaxCustomGrants)
	}
	for k, _ := range GrantStrings {
		if k&GrantSectionCustom > 0 {
			delete(GrantStrings, k)
		}
	}
	i := 0
	for _, g := range grants {
		// Only add grants that we don't know about
		if t, _ := ToGrant(g); t == GrantUnknown {
			i += 1
			shift := 15 + i
			v = Grant((1 << shift) & GrantSectionCustom)
			GrantStrings[v] = g
		}
	}
	return nil
}

// Clean returns a grant "cleansed" of unused/reserved bits. If the grant
// contains a self-terminating grant (E.g. GrantNone), that is returned instead.
func (g Grant) Clean() Grant {
	if (g & GrantNone) == GrantNone {
		return GrantNone
	}
	filter := GrantAuthenticated
	if IsCustomGrantsSet() {
		filter |= GrantSectionCustom
	}
	return g & filter
}

// Short returns the short name of the access grant. If the grant is not mapped
// to a short name, a comma-separated string representation is returned instead
// (IE. Grant.String() is called instead).
func (g Grant) Short() string {
	// Shorten known grants
	mask := ^GrantSectionCustom & ^GrantSectionReserved
	grant := g & mask
	s, ok := GrantStrings[grant]
	if !ok {
		s = grant.String()
	}
	// Add custom grants
	mask = GrantSectionCustom
	customGrant := g & mask
	if customGrant != GrantUnknown {
		if other := customGrant.String(); other != "" {
			// If there are no other grants set the string to custom
			// grants otherwise append the custom grants to the end.
			if grant == GrantUnknown {
				s = other
			} else {
				s = strings.Join(
					[]string{s, other},
					GrantDelimiter,
				)
			}
		}
	}
	return s
}

// String returns the comma-separated string representation of the access grant.
func (g Grant) String() string {
	var grants []string
	var i uint32 = 0
	for ; i < 32; i++ {
		v := (1 << i) & g
		switch v {
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
		default:
			// Append custom claims
			if v&GrantSectionCustom > 0 {
				if s, ok := GrantStrings[v]; ok {
					grants = append(grants, s)
				}
			}
		}
	}
	if len(grants) == 0 {
		return GrantStrings[GrantUnknown]
	}
	return strings.Join(grants, GrantDelimiter)
}
