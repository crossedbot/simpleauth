package controller

import (
	"net/http"

	"github.com/crossedbot/common/golang/server"
	middleware "github.com/crossedbot/simplemiddleware"
)

// Routes represent the authentication HTTP service routes.
var Routes = []server.Route{
	server.Route{
		Handler:          Login,
		Method:           http.MethodPost,
		Path:             "/users/login",
		ResponseSettings: []server.ResponseSetting{},
	},
	server.Route{
		Handler:          SignUp,
		Method:           http.MethodPost,
		Path:             "/users/signup",
		ResponseSettings: []server.ResponseSetting{},
	},
	server.Route{
		Handler:          middleware.Authorize(RefreshToken),
		Method:           http.MethodGet,
		Path:             "/users/refresh",
		ResponseSettings: []server.ResponseSetting{},
	},
	server.Route{
		Handler:          middleware.Authorize(SetTotp),
		Method:           http.MethodPost,
		Path:             "/otp",
		ResponseSettings: []server.ResponseSetting{},
	},
	server.Route{
		Handler:          middleware.Authorize(ValidateOtp),
		Method:           http.MethodGet,
		Path:             "/otp/validate/:otp",
		ResponseSettings: []server.ResponseSetting{},
	},
	server.Route{
		Handler:          middleware.Authorize(GetOtpQr),
		Method:           http.MethodGet,
		Path:             "/otp/qr",
		ResponseSettings: []server.ResponseSetting{},
	},
	server.Route{
		Handler:          GetJwk,
		Method:           http.MethodGet,
		Path:             "/.well-known/jwks.json",
		ResponseSettings: []server.ResponseSetting{},
	},
}
