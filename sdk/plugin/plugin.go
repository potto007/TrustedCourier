package plugin

import (
	"context"
	"crypto/fips140"
	"errors"
	"fmt"
	"os"

	"github.com/potto007/TrustedCourier/sdk/plugin/internal/contract"
	"github.com/potto007/TrustedCourier/sdk/plugin/internal/harden"
	"github.com/potto007/TrustedCourier/sdk/plugin/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Backend connects TrustedCourier to one kind of Backend. Locations are the
// Backend's own addressing, such as a KV path; TrustedCourier maps Secret
// Names to them and never shows them to Agents.
//
// Methods may be called concurrently.
type Backend interface {
	// Get returns the value at location, or an error wrapping ErrNotFound
	// when the Backend holds nothing there.
	Get(ctx context.Context, location string) ([]byte, error)
	// List returns the locations the Backend holds that start with prefix.
	List(ctx context.Context, prefix string) ([]string, error)
	// Health reports whether the Backend is reachable and usable. A nil
	// error means healthy; detail is shown to the Operator either way.
	Health(ctx context.Context) (detail string, err error)
	// Capabilities reports the optional features this Backend supports.
	Capabilities() Capabilities
}

// CourierKeyWriter is implemented by a Backend that can store Courier Keys
// (ADR-0001). It is used only when Capabilities reports CourierKeyWrite.
type CourierKeyWriter interface {
	WriteCourierKey(ctx context.Context, location string, value []byte) error
}

// Capabilities are a Backend's optional features.
type Capabilities struct {
	// CourierKeyWrite means the Backend implements CourierKeyWriter and
	// TrustedCourier may store Courier Keys in it.
	CourierKeyWrite bool
}

// Names lists the enabled capabilities as the core reports them.
func (c Capabilities) Names() []string {
	names := []string{}
	if c.CourierKeyWrite {
		names = append(names, "courier-key-write")
	}
	return names
}

var (
	// ErrNotFound means the Backend holds nothing at a location.
	ErrNotFound = errors.New("not found")
	// ErrUnsupported means the Backend does not support an operation.
	ErrUnsupported = errors.New("not supported by this Backend Plugin")
)

// Serve serves b as a Backend Plugin and does not return. Call it from main.
// It exits with an error if b declares CourierKeyWrite without implementing
// CourierKeyWriter.
//
// Serve hardens the plugin process the way the core hardens itself: core
// dumps are disabled before the first Secret is handled, and it exits if
// that fails. It reports whether the process runs in FIPS 140-3 mode
// (crypto/fips140), which a core in FIPS mode requires (ADR-0004); the
// core passes its own GODEBUG to the plugin, so a plugin built with the
// SDK runs in the mode the core does.
func Serve(b Backend) {
	if err := harden.DisableCoreDumps(); err != nil {
		fmt.Fprintln(os.Stderr, "plugin: disable core dumps:", err)
		os.Exit(1)
	}
	if b.Capabilities().CourierKeyWrite {
		if _, ok := b.(CourierKeyWriter); !ok {
			fmt.Fprintln(os.Stderr, "plugin: Backend declares CourierKeyWrite but does not implement CourierKeyWriter")
			os.Exit(1)
		}
	}
	protocol.Serve(&server{backend: b})
}

// server adapts a Backend to the wire protocol, holding it to the same
// contract the core enforces so Plugin Authors see violations as errors
// from their own plugin.
type server struct {
	protocol.UnimplementedBackendServer
	backend Backend
}

func (s *server) Capabilities(context.Context, *protocol.CapabilitiesRequest) (*protocol.CapabilitiesResponse, error) {
	return &protocol.CapabilitiesResponse{
		CourierKeyWrite: s.backend.Capabilities().CourierKeyWrite,
		Fips140Enabled:  fips140.Enabled(),
		Fips140Version:  fips140.Version(),
	}, nil
}

func (s *server) Health(ctx context.Context, _ *protocol.HealthRequest) (*protocol.HealthResponse, error) {
	detail, err := s.backend.Health(ctx)
	if cerr := contract.Detail(detail); cerr != nil {
		return nil, malformed(cerr)
	}
	if err == nil {
		return &protocol.HealthResponse{Healthy: true, Detail: detail}, nil
	}
	// The error says what is wrong; the detail still describes the Backend.
	msg := err.Error()
	if detail != "" {
		msg += " (" + detail + ")"
	}
	return &protocol.HealthResponse{Detail: contract.Sanitize(msg)}, nil
}

func (s *server) Get(ctx context.Context, req *protocol.GetRequest) (*protocol.GetResponse, error) {
	if err := contract.Location(req.GetLocation()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	value, err := s.backend.Get(ctx, req.GetLocation())
	if err != nil {
		return nil, toStatus(err)
	}
	if err := contract.Value(value); err != nil {
		return nil, malformed(err)
	}
	return &protocol.GetResponse{Value: value}, nil
}

func (s *server) List(ctx context.Context, req *protocol.ListRequest) (*protocol.ListResponse, error) {
	if err := contract.Prefix(req.GetPrefix()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	locations, err := s.backend.List(ctx, req.GetPrefix())
	if err != nil {
		return nil, toStatus(err)
	}
	if err := contract.List(req.GetPrefix(), locations); err != nil {
		return nil, malformed(err)
	}
	return &protocol.ListResponse{Locations: locations}, nil
}

func (s *server) WriteCourierKey(ctx context.Context, req *protocol.WriteCourierKeyRequest) (*protocol.WriteCourierKeyResponse, error) {
	w, ok := s.backend.(CourierKeyWriter)
	if !ok || !s.backend.Capabilities().CourierKeyWrite {
		return nil, status.Error(codes.Unimplemented, ErrUnsupported.Error())
	}
	if err := contract.Location(req.GetLocation()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := contract.Value(req.GetValue()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := w.WriteCourierKey(ctx, req.GetLocation(), req.GetValue()); err != nil {
		return nil, toStatus(err)
	}
	return &protocol.WriteCourierKeyResponse{}, nil
}

func malformed(err error) error {
	return status.Error(codes.Internal, "Backend Plugin produced a malformed response: "+err.Error())
}

func toStatus(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return status.Error(codes.NotFound, ErrNotFound.Error())
	case errors.Is(err, ErrUnsupported):
		return status.Error(codes.Unimplemented, ErrUnsupported.Error())
	default:
		return status.Error(codes.Unavailable, contract.Sanitize(err.Error()))
	}
}
