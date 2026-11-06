package winservice

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"time"

	p "netlaunch/internal/serviceprotocol"
)

// Capture is invoked only after a complete message was read, because named
// pipe impersonation authenticates the last message read, not JSON claims.
type PeerCapture func() (VerifiedPrincipal, error)

func (b *Broker) ServeConnection(lifetime context.Context, in io.Reader, out io.Writer, capture PeerCapture) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), p.MaxFrame+1)
	for {
		setFrameDeadline(in)
		if !scanner.Scan() {
			break
		}
		request, decodeErr := p.DecodeRequest(scanner.Bytes())
		response := p.Response{}
		if decodeErr != nil {
			response.Error = safeError("INVALID_REQUEST")
		} else {
			principal, err := capture()
			if err != nil || !principal.Verified() {
				response.Error = safeError("ACCESS_DENIED")
			} else {
				ctx, cancel := context.WithTimeout(lifetime, 5*time.Second)
				switch request.Method {
				case "snapshot":
					value, err := b.Snapshot(ctx, principal, request.ProfileID)
					if err == nil {
						response.Snapshot = &value
					} else {
						response.Error = wireError(err)
					}
				case "operation":
					value, err := b.Operation(ctx, principal, request.OperationID)
					if err == nil {
						response.Operation = &value
					} else {
						response.Error = wireError(err)
					}
				case "submit":
					value, err := b.Submit(ctx, principal, *request.Mutation)
					if err == nil {
						response.Operation = &value
					} else {
						response.Error = wireError(err)
					}
				}
				cancel()
				principal.Close()
			}
		}
		data, err := json.Marshal(response)
		if err != nil {
			return err
		}
		if len(data) > p.MaxFrame {
			return safeError("FRAME_TOO_LARGE")
		}
		setFrameDeadline(out)
		if _, err = out.Write(append(data, '\n')); err != nil {
			return nil
		}
	}
	return scanner.Err()
}
func wireError(err error) *p.Error {
	if typed, ok := err.(*p.Error); ok {
		return typed
	}
	return safeError("SERVICE_REQUEST_FAILED")
}
