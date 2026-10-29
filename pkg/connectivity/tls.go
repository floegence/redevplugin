package connectivity

import "crypto/tls"

func validatedTLSConfig(config *tls.Config, destination Destination) (*tls.Config, error) {
	if config == nil {
		return nil, nil
	}
	if destination.Transport == TransportUDP || destination.Scheme == "http" || destination.Scheme == "ws" || config.InsecureSkipVerify || (config.ServerName != "" && config.ServerName != destination.Host) {
		return nil, ErrConnectorDenied
	}
	value := config.Clone()
	value.ServerName = destination.Host
	if value.MinVersion < tls.VersionTLS12 {
		value.MinVersion = tls.VersionTLS12
	}
	if value.MaxVersion != 0 && value.MaxVersion < value.MinVersion {
		return nil, ErrConnectorDenied
	}
	return value, nil
}
