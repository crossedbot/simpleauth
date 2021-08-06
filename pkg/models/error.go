package models

import (
	"fmt"
)

const (
	ErrFailedConversionCode = iota + 1000
	ErrProcessingRequestCode
	ErrRequiredParamCode
	ErrUnauthorizedCode
)

type Error struct {
	Code    int
	Message string
}

func (err Error) Error() string {
	return fmt.Sprintf("%d: %s", err.Code, err.Message)
}
