//go:build !darwin && !linux

package authoring

import (
	"errors"
	"os"
)

func lockAuthorState(string) (*os.File, error) {
	return nil, errors.New("persistent author state requires a supported Darwin or Linux host")
}
