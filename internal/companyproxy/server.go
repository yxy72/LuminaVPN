// Package companyproxy exposes the authenticated, loopback-only TCP ingress for
// company egress. Address authorization and interface binding remain in Dial.
package companyproxy

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"netlaunch/internal/policy"
)

type Dial func(context.Context, string, int) (net.Conn, error)
type Credentials struct{ Username, Password string }

type Server struct {
	credentials Credentials
	dial        Dial
}

func New(credentials Credentials, dial Dial) (*Server, error) {
	if len(credentials.Username) == 0 || len(credentials.Username) > 255 || len(credentials.Password) < 24 || len(credentials.Password) > 255 || dial == nil {
		return nil, errors.New("invalid company ingress configuration")
	}
	return &Server{credentials: credentials, dial: dial}, nil
}

// Serve owns and closes the supplied listener. Only IPv4 loopback TCP listeners
// are accepted; callers cannot accidentally expose this service on the LAN.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || addr.IP.To4() == nil || !addr.IP.IsLoopback() {
		listener.Close()
		return errors.New("company ingress requires IPv4 loopback")
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	var workers sync.WaitGroup
	defer workers.Wait()
	defer cancel()
	slots := make(chan struct{}, 128)
	for {
		c, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		workers.Add(1)
		go func() { defer workers.Done(); defer func() { <-slots }(); s.handle(ctx, c) }()
	}
}

func (s *Server) handle(parent context.Context, c net.Conn) {
	defer c.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var header [2]byte
	if _, err := io.ReadFull(c, header[:]); err != nil || header[0] != 5 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	hasAuth := false
	for _, m := range methods {
		hasAuth = hasAuth || m == 2
	}
	if !hasAuth {
		write(c, []byte{5, 255})
		return
	}
	if write(c, []byte{5, 2}) != nil {
		return
	}
	if _, err := io.ReadFull(c, header[:]); err != nil || header[0] != 1 {
		return
	}
	user := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, user); err != nil {
		return
	}
	var length [1]byte
	if _, err := io.ReadFull(c, length[:]); err != nil {
		return
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(c, password); err != nil {
		return
	}
	validUser := subtle.ConstantTimeCompare(user, []byte(s.credentials.Username))
	validPassword := subtle.ConstantTimeCompare(password, []byte(s.credentials.Password))
	if validUser&validPassword != 1 {
		write(c, []byte{1, 1})
		return
	}
	if write(c, []byte{1, 0}) != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(c, request[:]); err != nil {
		return
	}
	if request[0] != 5 || request[1] != 1 || request[2] != 0 {
		reply(c, 7)
		return
	}
	target := ""
	switch request[3] {
	case 3:
		if _, err := io.ReadFull(c, length[:]); err != nil {
			return
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(c, name); err != nil {
			return
		}
		target = strings.ToLower(strings.TrimSuffix(string(name), "."))
		if !policy.ValidDomain(target) {
			reply(c, 8)
			return
		}
	case 1:
		var ip [4]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return
		}
		target = net.IP(ip[:]).String()
		if _, err := policy.IPv4(target); err != nil {
			reply(c, 8)
			return
		}
	default:
		reply(c, 8)
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return
	}
	p := int(binary.BigEndian.Uint16(port[:]))
	if p == 0 {
		reply(c, 2)
		return
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	upstream, err := s.dial(dialCtx, target, p)
	dialCancel()
	if err != nil || upstream == nil {
		if upstream != nil {
			upstream.Close()
		}
		reply(c, 2)
		return
	}
	defer upstream.Close()
	closeUpstream := context.AfterFunc(ctx, func() { upstream.Close() })
	defer closeUpstream()
	if reply(c, 0) != nil {
		return
	}
	c.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		io.Copy(upstream, c)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(done)
	}()
	io.Copy(c, upstream)
	c.Close()
	upstream.Close()
	<-done
}

func write(w io.Writer, b []byte) error {
	_, err := io.Copy(w, strings.NewReader(string(b)))
	return err
}
func reply(c net.Conn, code byte) error { return write(c, []byte{5, code, 0, 1, 127, 0, 0, 1, 0, 0}) }

// Proxy returns only the core fields owned by this ingress. The credentials
// must be persisted exclusively in the private per-run core configuration.
func Proxy(address string, credentials Credentials) (map[string]any, error) {
	host, raw, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(raw)
	if err != nil || ip == nil || ip.To4() == nil || !ip.IsLoopback() || port < 1 || port > 65535 {
		return nil, errors.New("invalid local company ingress address")
	}
	if _, err = New(credentials, func(context.Context, string, int) (net.Conn, error) { return nil, nil }); err != nil {
		return nil, err
	}
	return map[string]any{"name": "CORP-BOUND", "type": "socks5", "server": host, "port": port, "username": credentials.Username, "password": credentials.Password, "udp": false}, nil
}
