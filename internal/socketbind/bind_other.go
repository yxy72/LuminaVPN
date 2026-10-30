//go:build !windows

package socketbind

import (
	"context"
	"fmt"
	"net"
)

func dialInterface(context.Context, uint32, string) (net.Conn, error) {
	return nil, fmt.Errorf("socketbind: Windows is required")
}
