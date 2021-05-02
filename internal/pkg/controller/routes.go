package controller

import (
	"net/http"

	"github.com/crossedbot/common/golang/server"
)

type Route struct {
	Handler          server.Handler
	Method           string
	Path             string
	ResponseSettings []server.ResponseSetting
}

var Routes = []Route{
	Route{
		Login,
		http.MethodPost,
		"/users/login",
		[]server.ResponseSetting{},
	},
	Route{
		SignUp,
		http.MethodPost,
		"/users/signup",
		[]server.ResponseSetting{},
	},
	Route{
		Authenticate(RefreshToken),
		http.MethodGet,
		"/users/refresh",
		[]server.ResponseSetting{},
	},
	Route{
		Authenticate(SetTotp),
		http.MethodPost,
		"/otp",
		[]server.ResponseSetting{},
	},
	Route{
		Authenticate(ValidateOtp),
		http.MethodGet,
		"/otp/validate/:otp",
		[]server.ResponseSetting{},
	},
	Route{
		Authenticate(GetOtpQr),
		http.MethodGet,
		"/otp/qr",
		[]server.ResponseSetting{},
	},
}
