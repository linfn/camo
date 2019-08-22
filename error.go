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
	msg := e.msg
	if msg == "" {
		msg = http.StatusText(e.status)
	}
	if msg == "" {
		return fmt.Sprintf("code %d", e.status)
	}
	return fmt.Sprintf("code %d: %s", e.status, msg)
}

func getStatusCode(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if err, ok := err.(*statusError); ok {
		return err.StatusCode()
	}
	return http.StatusInternalServerError
}

func isStatusRetryable(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}
