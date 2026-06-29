package bridge

import "time"

type SurfaceSession struct {
	PluginInstanceID  string    `json:"plugin_instance_id"`
	SurfaceInstanceID string    `json:"surface_instance_id"`
	SurfaceID         string    `json:"surface_id"`
	ActiveFingerprint string    `json:"active_fingerprint"`
	BridgeNonce       string    `json:"bridge_nonce"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type AssetTicket struct {
	TicketID          string    `json:"ticket_id"`
	PluginInstanceID  string    `json:"plugin_instance_id"`
	SurfaceInstanceID string    `json:"surface_instance_id"`
	ActiveFingerprint string    `json:"active_fingerprint"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type GatewayToken struct {
	TokenID           string    `json:"token_id"`
	PluginInstanceID  string    `json:"plugin_instance_id"`
	SurfaceInstanceID string    `json:"surface_instance_id"`
	BridgeChannelID   string    `json:"bridge_channel_id"`
	PolicyRevision    uint64    `json:"policy_revision"`
	RevokeEpoch       uint64    `json:"revoke_epoch"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type Handshake struct {
	PluginID          string `json:"plugin_id"`
	SurfaceID         string `json:"surface_id"`
	SurfaceInstanceID string `json:"surface_instance_id"`
	ActiveFingerprint string `json:"active_fingerprint"`
	BridgeNonce       string `json:"bridge_nonce"`
	UIProtocolVersion string `json:"ui_protocol_version"`
}

type CallRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Params any    `json:"params,omitempty"`
}
