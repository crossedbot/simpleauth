package controller

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/crossedbot/common/golang/logger"
	"github.com/crossedbot/common/golang/server"

	"github.com/crossedbot/simpleauth/internal/pkg/models"
)

func Login(w http.ResponseWriter, r *http.Request, p server.Parameters) {
	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		logger.Error(err)
		server.JsonResponse(
			w, models.Error{
				Code:    models.ErrFailedConversionCode,
				Message: fmt.Sprintf("Failed to parse request body; %s", err),
			},
			http.StatusBadRequest,
		)
		return
	}
	tkn, err := V1().Login(user)
	if err == ErrorBadCredentials {
		logger.Error(err)
		server.JsonResponse(
			w, models.Error{
				Code:    models.ErrProcessingRequestCode,
				Message: fmt.Sprintf("Failed to login; %s", err),
			},
			http.StatusBadRequest,
		)
	} else if err != nil {
		logger.Error(err)
		server.JsonResponse(
			w, models.Error{
				Code:    models.ErrProcessingRequestCode,
				Message: fmt.Sprintf("Failed to login; %s", err),
			},
			http.StatusInternalServerError,
		)
		return
	}
	server.JsonResponse(w, &tkn, http.StatusOK)
}

func SignUp(w http.ResponseWriter, r *http.Request, p server.Parameters) {
	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		logger.Error(err)
		server.JsonResponse(
			w, models.Error{
				Code:    models.ErrFailedConversionCode,
				Message: fmt.Sprintf("Failed to parse request body; %s", err),
			},
			http.StatusBadRequest,
		)
		return
	}
	tkn, err := V1().SignUp(user)
	if err != nil {
		logger.Error(err)
		server.JsonResponse(
			w,
			models.Error{
				Code:    models.ErrProcessingRequestCode,
				Message: fmt.Sprintf("Failed to signup; %s", err),
			},
			http.StatusInternalServerError,
		)
		return
	}
	server.JsonResponse(w, &tkn, http.StatusCreated)
}

func SetTotp(w http.ResponseWriter, r *http.Request, p server.Parameters) {
	uid, _ := r.Context().Value(ClaimUserID).(string)
	var totp models.Totp
	if err := json.NewDecoder(r.Body).Decode(&totp); err != nil {
		logger.Error(err)
		server.JsonResponse(
			w, models.Error{
				Code:    models.ErrFailedConversionCode,
				Message: fmt.Sprintf("Failed to parse request body; %s", err),
			},
			http.StatusBadRequest,
		)
		return
	}
	newTotp, err := V1().SetTotp(uid, totp)
	if err != nil {
		logger.Error(err)
		server.JsonResponse(
			w, models.Error{
				Code:    models.ErrProcessingRequestCode,
				Message: fmt.Sprintf("Failed to set totp; %s", err),
			},
			http.StatusInternalServerError,
		)
		return
	}
	server.JsonResponse(w, &newTotp, http.StatusOK)
}

func ValidateOtp(w http.ResponseWriter, r *http.Request, p server.Parameters) {
	uid, _ := r.Context().Value(ClaimUserID).(string)
	otp := p.Get("otp")
	if otp == "" {
		server.JsonResponse(
			w, models.Error{
				Code:    models.ErrRequiredParamCode,
				Message: "Path parameter 'otp' is required",
			},
			http.StatusBadRequest,
		)
		return
	}
	tkn, err := V1().ValidateOtp(uid, otp)
	if err != nil {
		logger.Error(err)
		server.JsonResponse(
			w, models.Error{
				Code:    models.ErrProcessingRequestCode,
				Message: fmt.Sprintf("Failed to validate otp; %s", err),
			},
			http.StatusInternalServerError,
		)
		return
	}
	server.JsonResponse(w, &tkn, http.StatusOK)
}

func GetOtpQr(w http.ResponseWriter, r *http.Request, p server.Parameters) {
	uid, _ := r.Context().Value(ClaimUserID).(string)
	qr, err := V1().GetOtpQr(uid)
	if err != nil {
		logger.Error(err)
		server.JsonResponse(
			w, models.Error{
				Code:    models.ErrProcessingRequestCode,
				Message: fmt.Sprintf("Failed to get otp qr; %s", err),
			},
			http.StatusInternalServerError,
		)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", qr)
}

func RefreshToken(w http.ResponseWriter, r *http.Request, p server.Parameters) {
	uid, _ := r.Context().Value(ClaimUserID).(string)
	refreshedToken, err := V1().RefreshToken(uid)
	if err != nil {
		logger.Error(err)
		server.JsonResponse(
			w,
			models.Error{
				Code:    models.ErrProcessingRequestCode,
				Message: fmt.Sprintf("Failed to refresh access token; %s", err),
			},
			http.StatusInternalServerError,
		)
		return
	}
	server.JsonResponse(w, &refreshedToken, http.StatusOK)
}
