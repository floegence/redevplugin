package httpadapter

import (
	"github.com/floegence/redevplugin/v3/pkg/host"
)

func publicFeatures(features []host.Feature) []string {
	response := make([]string, len(features))
	for index, feature := range features {
		response[index] = string(feature)
	}
	return response
}
