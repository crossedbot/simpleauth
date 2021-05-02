package models

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestError(t *testing.T) {
	code := ErrRequiredParamCode
	msg := "hello world"
	expected := fmt.Sprintf("%d: %s", code, msg)
	actual := Error{code, msg}.Error()
	require.Equal(t, expected, actual)
}
