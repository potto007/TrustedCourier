// Package protocol is the wire protocol between the TrustedCourier core and
// a Backend Plugin: the generated gRPC service, the go-plugin handshake, and
// the glue that registers one with the other.
//
// Plugin Authors do not use this package; they call plugin.Serve. The core
// and the conformance kit reach it through the client package, which treats
// every response as untrusted input.
package protocol

import (
	"context"
	"errors"

	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// Handshake is the go-plugin handshake every Backend Plugin and the core
// share. ProtocolVersion changes only with an incompatible protocol change.
var Handshake = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "TRUSTEDCOURIER_BACKEND_PLUGIN",
	MagicCookieValue: "8f1d3c2a6b0e4f59a7c8d2e1b3f4a5c6",
}

// PluginName is the name the Backend service is dispensed under.
const PluginName = "backend"

// GRPCPlugin adapts the Backend service to go-plugin. Impl is set only on
// the plugin side.
type GRPCPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	Impl BackendServer
}

// GRPCServer registers Impl.
func (p *GRPCPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	if p.Impl == nil {
		return errors.New("protocol: GRPCPlugin has no Backend implementation")
	}
	RegisterBackendServer(s, p.Impl)
	return nil
}

// GRPCClient returns a BackendClient on conn.
func (p *GRPCPlugin) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, conn *grpc.ClientConn) (any, error) {
	return NewBackendClient(conn), nil
}

// Serve serves impl as a Backend Plugin over go-plugin and does not return.
// It performs no validation of impl's responses; plugin.Serve does.
func Serve(impl BackendServer) {
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins:         goplugin.PluginSet{PluginName: &GRPCPlugin{Impl: impl}},
		GRPCServer:      goplugin.DefaultGRPCServer,
	})
}
