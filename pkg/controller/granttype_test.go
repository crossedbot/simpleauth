package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGrantTypeString(t *testing.T) {
	tests := []struct {
		GrantType GrantType
		Expected  string
	}{
		{GrantTypeUnknown, GrantTypeStrings[int(GrantTypeUnknown)]},
		{GrantTypeNone, GrantTypeStrings[int(GrantTypeNone)]},
		{GrantTypeAuthenticated, GrantTypeStrings[int(GrantTypeAuthenticated)]},
		{GrantTypeOTP, GrantTypeStrings[int(GrantTypeOTP)]},
		{GrantTypeSetOTP, GrantTypeStrings[int(GrantTypeSetOTP)]},
		{GrantTypeOTPValidate, GrantTypeStrings[int(GrantTypeOTPValidate)]},
		{GrantTypeOTPQR, GrantTypeStrings[int(GrantTypeOTPQR)]},
		{GrantTypeUsersRefresh, GrantTypeStrings[int(GrantTypeUsersRefresh)]},
	}
	for _, test := range tests {
		require.Equal(t, test.Expected, test.GrantType.String())
	}
}
