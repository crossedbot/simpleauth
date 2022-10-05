package grants

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	middleware "github.com/crossedbot/simplemiddleware"
	"github.com/stretchr/testify/require"
)

func TestContainsGrant(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "hello.world/test", nil)
	require.Nil(t, err)

	ctx := req.Context()
	ctx = context.WithValue(ctx, middleware.ClaimGrant,
		GrantAuthenticated.String())
	req = req.WithContext(ctx)
	require.Nil(t, ContainsGrant(GrantOTP, req))
	require.Nil(t, ContainsGrant(GrantOTPValidate, req))
	require.Nil(t, ContainsGrant(GrantUsersRefresh, req))

	ctx = req.Context()
	ctx = context.WithValue(ctx, middleware.ClaimGrant,
		GrantUsersRefresh.String())
	req = req.WithContext(ctx)
	require.NotNil(t, ContainsGrant(GrantOTP, req))
	require.NotNil(t, ContainsGrant(GrantOTPValidate, req))
	require.NotNil(t, ContainsGrant(GrantAuthenticated, req))
	require.Nil(t, ContainsGrant(GrantUsersRefresh, req))

	ctx = req.Context()
	ctx = context.WithValue(ctx, middleware.ClaimGrant,
		GrantStrings[GrantAuthenticated])
	req = req.WithContext(ctx)
	require.Nil(t, ContainsGrant(GrantOTP, req))
	require.Nil(t, ContainsGrant(GrantOTPValidate, req))
	require.Nil(t, ContainsGrant(GrantUsersRefresh, req))
	require.Nil(t, ContainsGrant(GrantAuthenticated, req))
	require.NotNil(t, ContainsGrant(GrantFull, req))
}

func TestToGrant(t *testing.T) {
	tests := []struct {
		Str         string
		Expected    Grant
		ExpectedErr error
	}{
		{GrantStrings[GrantUnknown], GrantUnknown, nil},
		{GrantStrings[GrantNone], GrantNone, nil},
		{GrantStrings[GrantAuthenticated], GrantAuthenticated, nil},
		{GrantStrings[GrantSetOTP], GrantSetOTP, nil},
		{GrantStrings[GrantOTPValidate], GrantOTPValidate, nil},
		{GrantStrings[GrantOTPQR], GrantOTPQR, nil},
		{GrantStrings[GrantUsersRefresh], GrantUsersRefresh, nil},
		{"abc", GrantUnknown, errors.New("Unknown grant 'abc'")},
		{"abc,def", GrantUnknown, errors.New("Unknown grant 'abc'")},
		{
			strings.Join([]string{
				GrantStrings[GrantSetOTP],
				"abc",
				GrantStrings[GrantUsersRefresh],
			}, ","),
			GrantUnknown, errors.New("Unknown grant 'abc'"),
		},
		{
			strings.Join([]string{
				GrantStrings[GrantSetOTP],
				GrantStrings[GrantUnknown],
				GrantStrings[GrantOTPQR],
			}, ","),
			GrantSetOTP | GrantOTPQR, nil,
		},
		{
			strings.Join([]string{
				GrantStrings[GrantSetOTP],
				GrantStrings[GrantOTPValidate],
				GrantStrings[GrantOTPQR],
				GrantStrings[GrantUsersRefresh],
			}, ","),
			GrantAuthenticated, nil,
		},
		{
			strings.Join([]string{
				GrantStrings[GrantSetOTP],
				GrantStrings[GrantOTPQR],
			}, ","),
			GrantSetOTP | GrantOTPQR, nil,
		},
		{
			strings.Join([]string{
				GrantStrings[GrantOTPValidate],
				GrantStrings[GrantUsersRefresh],
			}, ","),
			GrantUsersRefresh | GrantOTPValidate, nil,
		},
	}
	for _, test := range tests {
		actual, err := ToGrant(test.Str)
		require.Equal(t, test.ExpectedErr, err)
		require.Equal(t, test.Expected, actual)
	}
}

func ToGrantCustom(t *testing.T) {
	customGrants := []string{"this", "that", "those"}
	tests := []struct {
		Str         string
		Expected    Grant
		ExpectedErr error
	}{
		{customGrants[0], Grant(0x010000), nil},
		{customGrants[1], Grant(0x020000), nil},
		{customGrants[2], Grant(0x040000), nil},
		{
			strings.Join([]string{
				customGrants[0],
				customGrants[2],
			}, ","),
			Grant(0x050000), nil,
		},
		{
			strings.Join([]string{
				customGrants[0],
				customGrants[1],
				customGrants[2],
			}, ","),
			Grant(0x070000), nil,
		},
	}
	err := SetCustomGrants(customGrants)
	require.Nil(t, err)
	for _, test := range tests {
		actual, err := ToGrant(test.Str)
		require.Equal(t, test.ExpectedErr, err)
		require.Equal(t, test.Expected, actual)
	}
}

func TestGetCustomGrant(t *testing.T) {
	customGrants := []string{"this", "that", "those"}
	tests := []struct {
		Limiters []string
		Expected Grant
	}{
		{
			[]string{},
			Grant(0x010000) | Grant(0x020000) | Grant(0x040000),
		},
		{
			[]string{"this", "those"},
			Grant(0x010000) | Grant(0x040000),
		},
		{
			[]string{"that"},
			Grant(0x020000),
		},
		{
			[]string{"not"},
			GrantUnknown,
		},
	}
	err := SetCustomGrants(customGrants)
	require.Nil(t, err)
	for _, test := range tests {
		require.Equal(
			t, test.Expected, GetCustomGrant(test.Limiters...))
	}
	SetCustomGrants([]string{})
}

func TestIsCustomGrantsSet(t *testing.T) {
	tests := []struct {
		Grants   []string
		Expected bool
	}{
		{[]string{"this", "that", "those"}, true},
		{[]string{}, false},
		{[]string{"this", "that"}, true},
	}
	for _, test := range tests {
		err := SetCustomGrants(test.Grants)
		require.Nil(t, err)
		require.Equal(t, test.Expected, IsCustomGrantsSet())
	}
	SetCustomGrants([]string{})
}

func TestGrantClean(t *testing.T) {
	tests := []struct {
		Grant    Grant
		Expected Grant
	}{
		{Grant(0xFF000001), GrantNone},
		{GrantNone | GrantSetOTP, GrantNone},
		{GrantSetOTP, GrantSetOTP},
		{GrantAuthenticated, GrantAuthenticated},
		{GrantFull, GrantAuthenticated},
		{GrantMax, GrantNone},
	}
	for _, test := range tests {
		require.Equal(t, test.Expected, test.Grant.Clean())
	}
}

func TestGrantShort(t *testing.T) {
	tests := []struct {
		Grant    Grant
		Expected string
	}{
		{GrantUnknown, GrantStrings[GrantUnknown]},
		{GrantNone, GrantStrings[GrantNone]},
		{GrantSetOTP, GrantStrings[GrantSetOTP]},
		{GrantOTPValidate, GrantStrings[GrantOTPValidate]},
		{GrantOTPQR, GrantStrings[GrantOTPQR]},
		{GrantUsersRefresh, GrantStrings[GrantUsersRefresh]},
		{GrantOTP, GrantStrings[GrantOTP]},
		{GrantAuthenticated, GrantStrings[GrantAuthenticated]},
		{
			GrantSetOTP | GrantOTPQR,
			strings.Join([]string{
				GrantStrings[GrantSetOTP],
				GrantStrings[GrantOTPQR],
			}, ","),
		},
		{
			GrantUsersRefresh | GrantOTPValidate,
			strings.Join([]string{
				GrantStrings[GrantOTPValidate],
				GrantStrings[GrantUsersRefresh],
			}, ","),
		},
	}
	for _, test := range tests {
		require.Equal(t, test.Expected, test.Grant.Short())
	}
}

func TestGrantShortCustom(t *testing.T) {
	customGrants := []string{"this", "that", "those"}
	customGrantsStr := strings.Join(customGrants, GrantDelimiter)
	err := SetCustomGrants(customGrants)
	require.Nil(t, err)
	tests := []struct {
		Grant    Grant
		Expected string
	}{
		{Grant(0x010000), customGrants[0]},
		{Grant(0x020000), customGrants[1]},
		{Grant(0x040000), customGrants[2]},
		{GetCustomGrant(), customGrantsStr},
		{
			GrantAuthenticated | GetCustomGrant(),
			strings.Join(
				[]string{
					GrantStrings[GrantAuthenticated],
					customGrantsStr,
				},
				GrantDelimiter,
			),
		},
		{
			GrantUsersRefresh | GrantSetOTP | GetCustomGrant(),
			strings.Join(
				[]string{
					GrantStrings[GrantSetOTP],
					GrantStrings[GrantUsersRefresh],
					customGrantsStr,
				},
				GrantDelimiter,
			),
		},
		{GrantOTP, GrantStrings[GrantOTP]},
		{GrantUnknown | GetCustomGrant(), customGrantsStr},
	}
	for _, test := range tests {
		require.Equal(t, test.Expected, test.Grant.Short())
	}
	SetCustomGrants([]string{})
}

func TestGrantString(t *testing.T) {
	tests := []struct {
		Grant    Grant
		Expected string
	}{
		{GrantUnknown, GrantStrings[GrantUnknown]},
		{GrantNone, GrantStrings[GrantNone]},
		{GrantSetOTP, GrantStrings[GrantSetOTP]},
		{GrantOTPValidate, GrantStrings[GrantOTPValidate]},
		{GrantOTPQR, GrantStrings[GrantOTPQR]},
		{GrantUsersRefresh, GrantStrings[GrantUsersRefresh]},
		{
			GrantAuthenticated,
			strings.Join([]string{
				GrantStrings[GrantSetOTP],
				GrantStrings[GrantOTPValidate],
				GrantStrings[GrantOTPQR],
				GrantStrings[GrantUsersRefresh],
			}, ","),
		},
		{
			GrantSetOTP | GrantOTPQR,
			strings.Join([]string{
				GrantStrings[GrantSetOTP],
				GrantStrings[GrantOTPQR],
			}, ","),
		},
		{
			GrantUsersRefresh | GrantOTPValidate,
			strings.Join([]string{
				GrantStrings[GrantOTPValidate],
				GrantStrings[GrantUsersRefresh],
			}, ","),
		},
	}
	for _, test := range tests {
		require.Equal(t, test.Expected, test.Grant.String())
	}
}

func TestGrantStringCustom(t *testing.T) {
	customGrants := []string{"this", "that", "those"}
	tests := []struct {
		Grant    Grant
		Expected string
	}{
		{Grant(0x010000), customGrants[0]},
		{Grant(0x020000), customGrants[1]},
		{Grant(0x040000), customGrants[2]},
		{
			Grant(0x050000),
			strings.Join([]string{
				customGrants[0],
				customGrants[2],
			}, ","),
		},
		{
			Grant(0x070000),
			strings.Join([]string{
				customGrants[0],
				customGrants[1],
				customGrants[2],
			}, ","),
		},
		{Grant(0x080000), GrantStrings[GrantUnknown]},
		{Grant(0x100000), GrantStrings[GrantUnknown]},
	}
	err := SetCustomGrants(customGrants)
	require.Nil(t, err)
	for _, test := range tests {
		require.Equal(t, test.Expected, test.Grant.String())
	}
	SetCustomGrants([]string{})
}
