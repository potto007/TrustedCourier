// Package client launches a Backend Plugin binary and calls it, treating
// every response as untrusted input: a response that breaks the protocol
// contract becomes an error, never a panic or a value passed on.
//
// The TrustedCourier core and the conformance kit use it. Plugin Authors do
// not need it.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"time"

	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/potto007/TrustedCourier/sdk/plugin"
	"github.com/potto007/TrustedCourier/sdk/plugin/internal/contract"
	"github.com/potto007/TrustedCourier/sdk/plugin/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// StartTimeout bounds launching a plugin through its first response.
const StartTimeout = 10 * time.Second

// Client is one running Backend Plugin process.
type Client struct {
	process *goplugin.Client
	rpc     protocol.BackendClient
	caps    plugin.Capabilities
}

// Start launches cmd, which must not be started, performs the handshake,
// and reads the plugin's capabilities. cmd.Env is passed as the plugin's
// whole environment. Plugin log output goes to logger.
func Start(cmd *exec.Cmd, logger hclog.Logger) (*Client, error) {
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	process := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig:  protocol.Handshake,
		Plugins:          goplugin.PluginSet{protocol.PluginName: &protocol.GRPCPlugin{}},
		Cmd:              cmd,
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		AutoMTLS:         true,
		SkipHostEnv:      true,
		StartTimeout:     StartTimeout,
		Logger:           logger,
		Stderr:           io.Discard,
		GRPCDialOptions: []grpc.DialOption{
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(contract.MaxMessageBytes)),
		},
	})
	c, err := dispense(process)
	if err != nil {
		process.Kill()
		return nil, err
	}
	return c, nil
}

func dispense(process *goplugin.Client) (*Client, error) {
	conn, err := process.Client()
	if err != nil {
		return nil, fmt.Errorf("start Backend Plugin: %s", contract.Sanitize(err.Error()))
	}
	raw, err := conn.Dispense(protocol.PluginName)
	if err != nil {
		return nil, fmt.Errorf("start Backend Plugin: %s", contract.Sanitize(err.Error()))
	}
	rpc, ok := raw.(protocol.BackendClient)
	if !ok {
		return nil, errors.New("start Backend Plugin: unexpected client type")
	}
	c := &Client{process: process, rpc: rpc}

	ctx, cancel := context.WithTimeout(context.Background(), StartTimeout)
	defer cancel()
	resp, err := rpc.Capabilities(ctx, &protocol.CapabilitiesRequest{})
	if err != nil {
		return nil, callError("Capabilities", err)
	}
	c.caps = plugin.Capabilities{CourierKeyWrite: resp.GetCourierKeyWrite()}
	return c, nil
}

// Capabilities returns the capabilities the plugin reported at start.
func (c *Client) Capabilities() plugin.Capabilities { return c.caps }

// Get returns the value at location. It returns an error wrapping
// plugin.ErrNotFound when the Backend holds nothing there.
func (c *Client) Get(ctx context.Context, location string) ([]byte, error) {
	if err := contract.Location(location); err != nil {
		return nil, fmt.Errorf("Get: %w", err)
	}
	resp, err := c.rpc.Get(ctx, &protocol.GetRequest{Location: location})
	if err != nil {
		return nil, callError("Get", err)
	}
	if err := contract.Value(resp.GetValue()); err != nil {
		clear(resp.GetValue()) // it may still be a Secret
		return nil, malformed("Get", err)
	}
	return resp.GetValue(), nil
}

// ValidateLocation reports whether loc is a Backend location the protocol
// accepts, so a config can be checked before any plugin call.
func ValidateLocation(loc string) error { return contract.Location(loc) }

// List returns the locations starting with prefix.
func (c *Client) List(ctx context.Context, prefix string) ([]string, error) {
	if err := contract.Prefix(prefix); err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	resp, err := c.rpc.List(ctx, &protocol.ListRequest{Prefix: prefix})
	if err != nil {
		return nil, callError("List", err)
	}
	if err := contract.List(prefix, resp.GetLocations()); err != nil {
		return nil, malformed("List", err)
	}
	return resp.GetLocations(), nil
}

// UnhealthyError is a plugin reporting its Backend unhealthy.
type UnhealthyError struct {
	Detail string
}

func (e *UnhealthyError) Error() string {
	if e.Detail == "" {
		return "unhealthy"
	}
	return "unhealthy: " + e.Detail
}

// Health returns the plugin's health detail when it reports healthy. An
// unhealthy report is an *UnhealthyError; any other error means the plugin
// could not answer properly.
func (c *Client) Health(ctx context.Context) (string, error) {
	resp, err := c.rpc.Health(ctx, &protocol.HealthRequest{})
	if err != nil {
		return "", callError("Health", err)
	}
	if err := contract.Detail(resp.GetDetail()); err != nil {
		return "", malformed("Health", err)
	}
	if !resp.GetHealthy() {
		return "", &UnhealthyError{Detail: resp.GetDetail()}
	}
	return resp.GetDetail(), nil
}

// WriteCourierKey stores a Courier Key at location. It returns an error
// wrapping plugin.ErrUnsupported unless the plugin reported CourierKeyWrite.
func (c *Client) WriteCourierKey(ctx context.Context, location string, value []byte) error {
	if !c.caps.CourierKeyWrite {
		return fmt.Errorf("WriteCourierKey: %w", plugin.ErrUnsupported)
	}
	if err := contract.Location(location); err != nil {
		return fmt.Errorf("WriteCourierKey: %w", err)
	}
	if err := contract.Value(value); err != nil {
		return fmt.Errorf("WriteCourierKey: %w", err)
	}
	if _, err := c.rpc.WriteCourierKey(ctx, &protocol.WriteCourierKeyRequest{Location: location, Value: value}); err != nil {
		return callError("WriteCourierKey", err)
	}
	return nil
}

// Exited reports whether the plugin process has exited.
func (c *Client) Exited() bool { return c.process.Exited() }

// PID returns the plugin's process ID.
func (c *Client) PID() int {
	pid, _ := strconv.Atoi(c.process.ID())
	return pid
}

// Kill stops the plugin process, gracefully if it responds, and waits for it
// to exit. It is safe to call more than once.
func (c *Client) Kill() { c.process.Kill() }

// callError turns a failed call into an error. The plugin chooses the status
// code and message, so only well-known codes are mapped and the message is
// sanitized.
func callError(method string, err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%s: %s", method, contract.Sanitize(err.Error()))
	}
	switch st.Code() {
	case codes.NotFound:
		return fmt.Errorf("%s: %w", method, plugin.ErrNotFound)
	case codes.Unimplemented:
		return fmt.Errorf("%s: %w", method, plugin.ErrUnsupported)
	default:
		return fmt.Errorf("%s: %s: %s", method, st.Code(), contract.Sanitize(st.Message()))
	}
}

func malformed(method string, err error) error {
	return fmt.Errorf("%s: malformed response from Backend Plugin: %w", method, err)
}
