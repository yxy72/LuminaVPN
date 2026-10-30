//go:build !darwin && !windows

package platform

import (
	"context"
	"errors"
	"net"
)

func BoundDial(string) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("platform interface binding is not enabled")
	}
}
