package sessionctx

import "context"

type PermissionSet struct {
	Read    bool `json:"read"`
	Write   bool `json:"write"`
	Execute bool `json:"execute"`
	Admin   bool `json:"admin"`
}

type Context struct {
	SessionChannelIDHash string        `json:"session_channel_id_hash"`
	OwnerUserHash        string        `json:"owner_user_hash"`
	OwnerEnvHash         string        `json:"owner_env_hash"`
	Origin               string        `json:"origin"`
	CSRFGeneration       string        `json:"csrf_generation"`
	Permissions          PermissionSet `json:"permissions"`
}

type Resolver interface {
	ResolveSession(ctx context.Context, channelID string) (Context, error)
}
