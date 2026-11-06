//go:build !windows

package winservice

import (
	"context"
	p "netlaunch/internal/serviceprotocol"
)

type unavailableClient struct{}

func NewClient() p.Client { return unavailableClient{} }
func (unavailableClient) Snapshot(context.Context, string) (p.Snapshot, error) {
	return p.Snapshot{ProtocolVersion: p.Version, ServiceState: "unavailable", TakeoverState: "unknown", RecoveryRequired: true}, safeError("WINDOWS_SERVICE_REQUIRED")
}
func (unavailableClient) Submit(context.Context, p.Mutation) (p.Operation, error) {
	return p.Operation{}, safeError("WINDOWS_SERVICE_REQUIRED")
}
func (unavailableClient) Operation(context.Context, string) (p.Operation, error) {
	return p.Operation{}, safeError("WINDOWS_SERVICE_REQUIRED")
}
