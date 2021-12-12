package controller

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/crossedbot/common/golang/server"
	jwt "github.com/crossedbot/simplejwt"
	middleware "github.com/crossedbot/simplemiddleware"

	"github.com/crossedbot/simpleauth/pkg/models"
)

const (
	AuthHeader       = "Authorization"
	ClaimUserID      = "uid"
	DefaultPublicKey = "~/.simpleauth/simpleauth.key.pub"
)

var (
	ErrUserIdDataType = errors.New("user ID claim is not a string")
)

var publicAuthKey []byte // XXX this is necessary for it to persist in keyFunc
var setAuthPublicKey = func(pubKey []byte) {
	publicAuthKey = pubKey
}

var authOnce sync.Once
var authenticator = func() (mw middleware.Middleware) {
	authOnce.Do(func() {
		keyFunc := func(token *middleware.Token) ([]byte, error) {
			return publicAuthKey, nil
		}
		errFunc := func(w http.ResponseWriter, err error) {
			server.JsonResponse(w, models.Error{
				Code:    models.ErrUnauthorizedCode,
				Message: err.Error(),
			}, http.StatusUnauthorized)
		}
		mw = middleware.New(AuthHeader, keyFunc, errFunc)
	})
	return
}()

func Authenticate(handler server.Handler) server.Handler {
	h := authenticator.Handle(func(w http.ResponseWriter, r *http.Request) {
		p := server.GetParameters(r.Context())
		userID, err := getUserIdFromRequest(r)
		if err != nil || userID == "" {
			server.JsonResponse(w,
				models.Error{
					Code:    models.ErrUnauthorizedCode,
					Message: "user identifier is missing or invalid",
				},
				http.StatusUnauthorized,
			)
			return
		}
		ctx := r.Context()
		r = r.WithContext(context.WithValue(ctx, ClaimUserID, userID))
		handler(w, r, p)
	})
	return server.NewHandler(h)
}

func getUserIdFromRequest(r *http.Request) (string, error) {
	tknStr := authenticator.Extract(r)
	tkn, err := jwt.Parse(tknStr)
	if err != nil {
		return "", err
	}
	userId, ok := tkn.Claims.Get(ClaimUserID).(string)
	if !ok {
		return "", ErrUserIdDataType
	}
	return userId, nil
}
