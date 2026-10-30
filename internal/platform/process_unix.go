//go:build !windows

package platform

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

func Process(pid int) (Identity, error) {
	if pid < 2 {
		return Identity{}, errors.New("invalid process id")
	}
	out, e := Command(context.Background(), "/bin/ps", "-ww", "-p", strconv.Itoa(pid), "-o", "state=", "-o", "lstart=", "-o", "comm=", "-o", "command=")
	if e != nil || strings.TrimSpace(out) == "" {
		return Identity{}, nil
	}
	fields := strings.Fields(out)
	if len(fields) < 8 || strings.HasPrefix(fields[0], "Z") {
		return Identity{}, nil
	}
	// Query the executable and command separately because executable paths can contain spaces.
	exe, e := Command(context.Background(), "/bin/ps", "-ww", "-p", strconv.Itoa(pid), "-o", "comm=")
	if e != nil {
		return Identity{}, nil
	}
	cmd, e := Command(context.Background(), "/bin/ps", "-ww", "-p", strconv.Itoa(pid), "-o", "command=")
	if e != nil {
		return Identity{}, nil
	}
	return Identity{PID: pid, Birth: strings.Join(fields[1:6], " "), Executable: strings.TrimSpace(exe), Command: strings.TrimSpace(cmd)}, nil
}
