package websecurity

import (
	"errors"
	"net/http"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

var (
	ErrOriginDenied = errors.New("request origin is denied")
	ErrCSRFRequired = errors.New("csrf token is required")
	ErrCSRFInvalid  = errors.New("csrf token is invalid")
)

type Guard interface {
	Authenticate(r *http.Request) (sessionctx.Context, error)
}
