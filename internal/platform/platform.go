package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"time"
)

type Network struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
	Gateway   string `json:"gateway"`
	Service   string `json:"service"`
}
type Identity struct {
	PID        int    `json:"pid"`
	Birth      string `json:"birth"`
	Executable string `json:"executable"`
	Command    string `json:"command"`
	OwnerSID   string `json:"owner_sid,omitempty"`
}
type Route struct {
	Prefix    string `json:"prefix"`
	Gateway   string `json:"gateway"`
	Interface string `json:"interface"`
	Scoped    bool   `json:"scoped"`
	Flags     string `json:"flags"`
}

func Command(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return "", errors.New("system command failed: " + name)
	}
	return string(out), nil
}
func FreePort() (int, error) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return 0, e
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func Available(port int) bool {
	return CheckPort(port) == nil
}

// CheckPort preserves bind failures so a permission error is not reported as
// another application occupying the port. Both transports are required by DNS.
func CheckPort(port int) error {
	l, e := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if e != nil {
		return fmt.Errorf("local TCP port %d bind failed: %w", port, e)
	}
	l.Close()
	u, e := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if e != nil {
		return fmt.Errorf("local UDP port %d bind failed: %w", port, e)
	}
	u.Close()
	return nil
}
