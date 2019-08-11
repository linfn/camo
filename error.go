package camo

import (
	"fmt"
	"net/http"
)

type statusError struct {
	status int
	msg    string
}

func (e *statusError) StatusCode() int {
	return e.status
}

func (e *statusError) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return http.StatusText(e.status)
}

// Error ...
func Error(code int, msg ...interface{}) error {
	return &statusError{
		status: code,
		msg:    fmt.Sprint(msg...),
	}
}

// GetStatusCode ...
func GetStatusCode(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if err, ok := err.(interface{ StatusCode() int }); ok {
		return err.StatusCode()
	}
	return http.StatusInternalServerError
}
