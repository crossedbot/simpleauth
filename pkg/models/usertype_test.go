package models

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserTypeString(t *testing.T) {
	expected := "USER"
	actual := BaseUserType.String()
	require.Equal(t, expected, actual)
	expected = "ADMIN"
	actual = AdminUserType.String()
	require.Equal(t, expected, actual)
}

func TestToUserType(t *testing.T) {
	expected := BaseUserType
	actual, err := ToUserType("USER")
	require.Nil(t, err)
	require.Equal(t, expected, actual)
	expected = AdminUserType
	actual, err = ToUserType("ADMIN")
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}
