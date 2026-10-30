// Package dnswire reads bounded TCP DNS replies from an explicitly bound resolver.
package dnswire

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"netlaunch/internal/policy"
)

type Answer struct {
	Domain     string    `json:"domain"`
	IP         string    `json:"ip"`
	DNS        string    `json:"dns"`
	ResolvedAt time.Time `json:"resolved_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	TTL        uint32    `json:"ttl"`
}
type Dial func(context.Context, string, string) (net.Conn, error)

func Query(ctx context.Context, dial Dial, server, host string) ([]Answer, error) {
	if !policy.ValidDomain(host) {
		return nil, errors.New("invalid DNS query name")
	}
	if _, err := policy.IPv4(server); err != nil {
		return nil, err
	}
	q := make([]byte, 12)
	if _, err := rand.Read(q[:2]); err != nil {
		return nil, err
	}
	q[2] = 1
	q[5] = 1
	for _, label := range strings.Split(host, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	c, err := dial(ctx, "tcp4", net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, errors.New("approved DNS connection failed")
	}
	defer c.Close()
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	// DialContext only covers connection establishment. Cancellation must also
	// interrupt a resolver that accepts TCP and then stops replying.
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	p := make([]byte, 2, len(q)+2)
	binary.BigEndian.PutUint16(p, uint16(len(q)))
	p = append(p, q...)
	if _, err = io.Copy(c, bytes.NewReader(p)); err != nil {
		return nil, errors.New("approved DNS write failed")
	}
	size := make([]byte, 2)
	if _, err = io.ReadFull(c, size); err != nil {
		return nil, errors.New("approved DNS reply missing")
	}
	n := binary.BigEndian.Uint16(size)
	if n < 12 {
		return nil, errors.New("short DNS reply")
	}
	reply := make([]byte, int(n))
	if _, err = io.ReadFull(c, reply); err != nil {
		return nil, errors.New("incomplete DNS reply")
	}
	return Parse(reply, binary.BigEndian.Uint16(q), host, server, time.Now())
}

func name(data []byte, at int) (string, int, error) {
	labels := []string{}
	next := -1
	seen := map[int]bool{}
	for jumps := 0; jumps < 128; jumps++ {
		if at < 0 || at >= len(data) || seen[at] {
			return "", 0, errors.New("invalid DNS name")
		}
		seen[at] = true
		n := int(data[at])
		if n&0xc0 == 0xc0 {
			if at+1 >= len(data) {
				break
			}
			if next < 0 {
				next = at + 2
			}
			at = (n&0x3f)<<8 | int(data[at+1])
			continue
		}
		if n&0xc0 != 0 || n > 63 {
			return "", 0, errors.New("invalid DNS label")
		}
		at++
		if n == 0 {
			if next < 0 {
				next = at
			}
			s := strings.ToLower(strings.Join(labels, "."))
			if len(s) > 253 {
				return "", 0, errors.New("DNS name too long")
			}
			return s, next, nil
		}
		if at+n > len(data) {
			break
		}
		labels = append(labels, string(data[at:at+n]))
		at += n
	}
	return "", 0, errors.New("truncated DNS name")
}

func Parse(data []byte, id uint16, host, server string, now time.Time) ([]Answer, error) {
	now = now.Round(0) // DNS lifetime must include time spent asleep.
	bad := errors.New("invalid or unsuccessful approved DNS response")
	if len(data) < 12 || len(data) > 65535 || binary.BigEndian.Uint16(data) != id {
		return nil, bad
	}
	flags := binary.BigEndian.Uint16(data[2:])
	if flags&0x8000 == 0 || flags&0x7a0f != 0 || binary.BigEndian.Uint16(data[4:]) != 1 {
		return nil, bad
	}
	q, at, err := name(data, 12)
	if err != nil || q != host || at+4 > len(data) || binary.BigEndian.Uint16(data[at:]) != 1 || binary.BigEndian.Uint16(data[at+2:]) != 1 {
		return nil, bad
	}
	at += 4
	type record struct {
		owner string
		ip    string
		alias string
		ttl   uint32
	}
	records := []record{}
	count := int(binary.BigEndian.Uint16(data[6:]))
	if count > 512 {
		return nil, bad
	}
	for i := 0; i < count; i++ {
		owner, end, e := name(data, at)
		if e != nil || end+10 > len(data) {
			return nil, bad
		}
		typ := binary.BigEndian.Uint16(data[end:])
		class := binary.BigEndian.Uint16(data[end+2:])
		ttl := binary.BigEndian.Uint32(data[end+4:])
		length := int(binary.BigEndian.Uint16(data[end+8:]))
		at = end + 10
		if at+length > len(data) {
			return nil, bad
		}
		r := record{owner: owner, ttl: ttl}
		if class == 1 && typ == 1 && length == 4 {
			r.ip = netip.AddrFrom4([4]byte(data[at : at+4])).String()
		}
		if class == 1 && typ == 5 {
			var e error
			var next int
			r.alias, next, e = name(data, at)
			if e != nil || next != at+length {
				return nil, bad
			}
		}
		if r.ip != "" || r.alias != "" {
			records = append(records, r)
		}
		at += length
	}
	// A CNAME chain is a single path, not a reachability graph. Reject cycles,
	// conflicting aliases and owners that mix CNAME and A records.
	allowed := map[string]uint32{}
	owner, pathTTL := host, ^uint32(0)
	for depth := 0; ; depth++ {
		if _, seen := allowed[owner]; seen || depth > 8 {
			return nil, bad
		}
		allowed[owner] = pathTTL
		alias, hasAddress := "", false
		for _, r := range records {
			if r.owner != owner {
				continue
			}
			hasAddress = hasAddress || r.ip != ""
			if r.alias != "" {
				if !policy.ValidDomain(r.alias) || (alias != "" && alias != r.alias) {
					return nil, bad
				}
				alias = r.alias
				if r.ttl < pathTTL {
					pathTTL = r.ttl
				}
			}
		}
		if alias == "" {
			break
		}
		if hasAddress {
			return nil, bad
		}
		owner = alias
	}
	answers := []Answer{}
	seen := map[string]int{}
	for _, r := range records {
		ttl, ok := allowed[r.owner]
		if !ok || r.ip == "" {
			continue
		}
		if r.ttl < ttl {
			ttl = r.ttl
		}
		if _, e := policy.IPv4(r.ip); e != nil {
			return nil, bad
		}
		if ttl > 300 {
			ttl = 300
		}
		if index, exists := seen[r.ip]; exists {
			if ttl < answers[index].TTL {
				answers[index].TTL = ttl
				answers[index].ExpiresAt = now.Add(time.Duration(ttl) * time.Second)
			}
			continue
		}
		seen[r.ip] = len(answers)
		answers = append(answers, Answer{host, r.ip, server, now, now.Add(time.Duration(ttl) * time.Second), ttl})
	}
	// Aggregate duplicates before discarding zero-TTL grants. A zero-TTL
	// duplicate must not leave another copy of the same address authorized.
	usable := answers[:0]
	for _, a := range answers {
		if a.TTL > 0 {
			usable = append(usable, a)
		}
	}
	answers = usable
	if len(answers) == 0 {
		return nil, errors.New("approved DNS returned no usable IPv4 lease")
	}
	return answers, nil
}
