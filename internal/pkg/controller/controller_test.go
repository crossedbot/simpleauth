package controller

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetDatabase(t *testing.T) {
	ctx := context.Background()
	ctr := &controller{ctx, nil, nil, ""}
	require.Nil(t, ctr.client)
	ctr.SetDatabase("mongodb://127.0.0.1:27017")
	require.NotNil(t, ctr.client)
}

func TestSetAuthPrivateKey(t *testing.T) {
	ctx := context.Background()
	ctr := &controller{ctx, nil, nil, ""}
	expected := []byte("Hello World")
	ctr.SetAuthPrivateKey(bytes.NewBuffer(expected))
	require.Equal(t, expected, ctr.privateKey)
}
