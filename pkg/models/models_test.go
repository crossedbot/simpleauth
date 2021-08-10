package models

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type TestDataItem struct {
	Value    string
	Expected interface{}
}

func TestValidEmailAddress(t *testing.T) {
	testData := []TestDataItem{
		// invalid email
		{"plaintext", false},
		// another invalid email
		{"hello@world", false},
		// local length greater-than 64
		{
			"aaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaa" +
				"a@example.com",
			false,
		},
		// server length greater-than 255
		{
			"hello@" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aa.com",
			false,
		},
		// weird but valid email
		{"very.unusual.\"@\".unusual.com@example.com", true},
		// valid email
		{"hello@world.com", true},
	}
	for _, data := range testData {
		b := ValidEmailAddress(data.Value)
		require.Equal(t, data.Expected, b)
	}
}

func TestValidUsername(t *testing.T) {
	testData := []TestDataItem{
		// length less-than 3
		{"aa", false},
		// length greater-than 255
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaa",
			false,
		},
		// starts with non-word character (IE. [^a-zA-Z0-9_])
		{".aaa", false},
		// ends with non-word character
		{"aaa.", false},
		// no repeating non-word characters
		{"a..aa", false},
		// valid username
		{"aaa", true},
		// non-repeating non-word characters
		{"a.a.a", true},
	}
	for _, data := range testData {
		b := ValidUsername(data.Value)
		require.Equal(t, data.Expected, b)
	}
}

func TestValidPhoneNumber(t *testing.T) {
	testData := []TestDataItem{
		{"+919367788755", true},
		{"8989829304", true},
		{"+16308520397", true},
		{"786-307-3615", true},
		{"789", false},
		{"123765", false},
		{"1-1-1", false},
		{"+982", false},
	}
	for _, data := range testData {
		b := ValidPhonenumber(data.Value)
		require.Equal(t, data.Expected, b)
	}
}

func TestUserValid(t *testing.T) {
	// Valid User
	user := User{
		FirstName: "Hello",
		LastName:  "World",
		Email:     "hello@world.com",
		Username:  "hello.world",
		Phone:     "+16308520397",
	}
	err := user.Valid()
	require.Nil(t, err)

	// length of first name greater-than 255
	user.FirstName = "aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaa"
	err = user.Valid()
	require.NotNil(t, err)

	// length of last name greater-than 255
	user.FirstName = "Hello"
	user.LastName = "aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaa"
	err = user.Valid()
	require.NotNil(t, err)

	// invalid email
	user.LastName = "World"
	user.Email = "plaintext"
	err = user.Valid()
	require.NotNil(t, err)

	// invalid username
	user.Email = "hello@world.com"
	user.Username = "hello..world"
	err = user.Valid()
	require.NotNil(t, err)

	// invalid phonenumber
	user.Username = "hello.world"
	user.Phone = "+123"
	err = user.Valid()
	require.NotNil(t, err)
}
