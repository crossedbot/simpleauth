package controller

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/crossedbot/common/golang/logger"
	"github.com/crossedbot/common/golang/server"
	middleware "github.com/crossedbot/simplemiddleware"

	"github.com/crossedbot/simpleauth/pkg/models"
)

func Login(w http.ResponseWriter, r *http.Request, p server.Parameters) {
	var login models.Login
	if err := json.NewDecoder(r.Body).Decode(&login); err != nil {
		logger.Error(err)
		server.JsonResponse(w, server.Error{
			Code: server.ErrFailedConversionCode,
			Message: fmt.Sprintf(
				"Failed to parse request body; %s",
				err,
			),
		}, http.StatusBadRequest)
		return
	}
	if login.Name == "" {
		server.JsonResponse(w, server.Error{
			Code: server.ErrProcessingRequestCode,
			Message: fmt.Sprintf(
				"Failed to login; %s",
				ErrorUsernameRequired,
			),
		}, http.StatusBadRequest)
		return
	}
	if login.Password == "" {
		server.JsonResponse(w, server.Error{
			Code: server.ErrProcessingRequestCode,
			Message: fmt.Sprintf(
				"Failed to login; %s",
				ErrorPasswordRequired,
			),
		}, http.StatusBadRequest)
		return
	}
	tkn, err := V1().Login(login)
	if err == ErrorBadCredentials {
		logger.Error(err)
		server.JsonResponse(w, server.Error{
			Code: server.ErrProcessingRequestCode,
			Message: fmt.Sprintf(
				"Failed to login; %s",
				err,
			),
		}, http.StatusBadRequest)
		return
	} else if err != nil {
		logger.Error(err)
		server.JsonResponse(w, server.Error{
			Code: server.ErrProcessingRequestCode,
			Message: fmt.Sprintf(
				"Failed to login; %s",
				err,
			),
		}, http.StatusInternalServerError)
		return
	}
	server.JsonResponse(w, &tkn, http.StatusOK)
}

func SignUp(w http.ResponseWriter, r *http.Request, p server.Parameters) {
	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		logger.Error(err)
		server.JsonResponse(w, server.Error{
			Code: server.ErrFailedConversionCode,
			Message: fmt.Sprintf(
				"Failed to parse request body; %s",
				err,
			),
		}, http.StatusBadRequest)
		return
	}
	if user.Username == "" && user.Email == "" {
		server.JsonResponse(w, server.Error{
			Code: server.ErrProcessingRequestCode,
			Message: fmt.Sprintf(
				"Failed to signup; %s",
				ErrorUsernameRequired,
			),
		}, http.StatusBadRequest)
		return
	}
	if user.Password == "" {
		server.JsonResponse(w, server.Error{
			Code: server.ErrProcessingRequestCode,
			Message: fmt.Sprintf(
				"Failed to signup; %s",
				ErrorPasswordRequired,
			),
		}, http.StatusBadRequest)
		return
	}
	if user.UserType == "" {
		user.UserType = models.BaseUserType.String()
	} else if _, err := models.ToUserType(user.UserType); err != nil {
		server.JsonResponse(w, server.Error{
			Code: server.ErrProcessingRequestCode,
			Message: fmt.Sprintf(
				"Failed to signup; %s",
				err,
			),
		}, http.StatusBadRequest)
		return
	}
	tkn, err := V1().SignUp(user)
	if err != nil {
		logger.Error(err)
		server.JsonResponse(w, server.Error{
			Code: server.ErrProcessingRequestCode,
			Message: fmt.Sprintf(
				"Failed to signup; %s",
				err,
			),
		}, http.StatusInternalServerError)
		return
	}
	server.JsonResponse(w, &tkn, http.StatusCreated)
}

func SetTotp(w http.ResponseWriter, r *http.Request, p server.Parameters) {
	uid, _ := r.Context().Value(middleware.ClaimUserId).(string)
	var totp models.Totp
	if err := json.NewDecoder(r.Body).Decode(&totp); err != nil {
		logger.Error(err)
		server.JsonResponse(w, server.Error{
			Code: server.ErrFailedConversionCode,
			Message: fmt.Sprintf(
				"Failed to parse request body; %s",
				err,
			),
		}, http.StatusBadRequest)
		return
	}
	newTotp, err := V1().SetTotp(uid, totp)
	if err != nil {
		logger.Error(err)
		server.JsonResponse(w, server.Error{
			Code: server.ErrProcessingRequestCode,
			Message: fmt.Sprintf(
				"Failed to set totp; %s",
				err,
			),
		}, http.StatusInternalServerError)
		return
	}
	server.JsonResponse(w, &newTotp, http.StatusOK)
}

func ValidateOtp(w http.ResponseWriter, r *http.Request, p server.Parameters) {
	uid, _ := r.Context().Value(middleware.ClaimUserId).(string)
	otp := p.Get("otp")
	if otp == "" {
		server.JsonResponse(w, server.Error{
			Code:    server.ErrRequiredParamCode,
			Message: "Path parameter 'otp' is required",
		}, http.StatusBadRequest)
		return
	}
	tkn, err := V1().ValidateOtp(uid, otp)
	if err != nil {
		logger.Error(err)
		server.JsonResponse(w, server.Error{
			Code: server.ErrProcessingRequestCode,
			Message: fmt.Sprintf(
				"Failed to validate otp; %s",
				err,
			),
		}, http.StatusInternalServerError)
		return
	}
	server.JsonResponse(w, &tkn, http.StatusOK)
}

func GetOtpQr(w http.ResponseWriter, r *http.Request, p server.Parameters) {
	uid, _ := r.Context().Value(middleware.ClaimUserId).(string)
	qr, err := V1().GetOtpQr(uid)
	if err != nil {
		logger.Error(err)
		server.JsonResponse(w, server.Error{
			Code: server.ErrProcessingRequestCode,
			Message: fmt.Sprintf(
				"Failed to get otp qr; %s",
				err,
			),
		}, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", qr)
}

func RefreshToken(w http.ResponseWriter, r *http.Request, p server.Parameters) {
	uid, _ := r.Context().Value(middleware.ClaimUserId).(string)
	refreshedToken, err := V1().RefreshToken(uid)
	if err != nil {
		logger.Error(err)
		server.JsonResponse(w, server.Error{
			Code: server.ErrProcessingRequestCode,
			Message: fmt.Sprintf(
				"Failed to refresh access token; %s",
				err,
			),
		}, http.StatusInternalServerError)
		return
	}
	server.JsonResponse(w, &refreshedToken, http.StatusOK)
}

func GetJwk(w http.ResponseWriter, r *http.Request, p server.Parameters) {
	jwks, err := V1().GetJwks()
	if err != nil {
		logger.Error(err)
		server.JsonResponse(w, server.Error{
			Code: server.ErrProcessingRequestCode,
			Message: fmt.Sprintf(
				"Failed to retrieve jwk.json; %s",
				err,
			),
		}, http.StatusInternalServerError)
		return
	}
	server.JsonResponse(w, &jwks, http.StatusOK)
}
