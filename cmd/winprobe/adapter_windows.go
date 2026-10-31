//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"net"
	"netlaunch/internal/platform"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winwfp"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

func stageRuntime(files securefile.AdminStore, id, root string) error {
	m, e := runtimebundle.Verify(root)
	if e != nil {
		return e
	}
	b, e := os.ReadFile(filepath.Join(root, "bin", "wintun.dll"))
	if e != nil {
		return e
	}
	sum := sha256.Sum256(b)
	match := false
	for _, f := range m.Files {
		if f.Path == "bin/wintun.dll" && f.SHA256 == hex.EncodeToString(sum[:]) {
			match = true
		}
	}
	if !match {
		return errors.New("Wintun hash mismatch")
	}
	return files.Bytes(filepath.Join(id, "wintun.dll"), b)
}

// The independent holder keeps the adapter alive while recovery reverses its
// journal. Only then does it close the exact handle that created the adapter.
func holdAdapter(files securefile.AdminStore, id, role string) error {
	var p plan
	if e := read(files, id, "probe-plan.json", &p); e != nil {
		return e
	}
	startTimer := time.NewTimer(p.Timeout)
	defer startTimer.Stop()
	for {
		var released bool
		if read(files, id, "probe-release"+role+".json", &released) == nil && released {
			return nil
		}
		var ready bool
		if read(files, id, "probe-go.json", &ready) == nil && ready {
			break
		}
		select {
		case <-startTimer.C:
			return errors.New("adapter start was not authorized before timeout")
		case <-time.After(50 * time.Millisecond):
		}
	}
	name := "NL-Probe-" + id[len("netlaunch-"):] + role
	rows, e := winnet.Adapters()
	if e != nil {
		return e
	}
	for _, a := range rows {
		if a.Name == name {
			return errors.New("probe adapter already exists")
		}
	}
	dll, e := windows.LoadDLL(filepath.Join(files.Root, id, "wintun.dll"))
	if e != nil {
		return e
	}
	defer dll.Release()
	create, e := dll.FindProc("WintunCreateAdapter")
	if e != nil {
		return e
	}
	closeAdapter, e := dll.FindProc("WintunCloseAdapter")
	if e != nil {
		return e
	}
	start, e := dll.FindProc("WintunStartSession")
	if e != nil {
		return e
	}
	end, e := dll.FindProc("WintunEndSession")
	if e != nil {
		return e
	}
	getLUID, e := dll.FindProc("WintunGetAdapterLUID")
	if e != nil {
		return e
	}
	n, _ := windows.UTF16PtrFromString(name)
	kind, _ := windows.UTF16PtrFromString("LuminaProbe")
	h, _, err := create.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(kind)), 0)
	if h == 0 {
		return fmt.Errorf("create probe adapter: %w", err)
	}
	defer closeAdapter.Call(h)
	s, _, err := start.Call(h, 0x20000)
	if s == 0 {
		return fmt.Errorf("start probe adapter: %w", err)
	}
	defer end.Call(s)
	pump, e := newPump(dll, s)
	if e != nil {
		return e
	}
	var luid uint64
	getLUID.Call(h, uintptr(unsafe.Pointer(&luid)))
	until := time.Now().Add(10 * time.Second)
	for {
		rows, e = winnet.Adapters()
		if e != nil {
			return e
		}
		found := false
		for _, a := range rows {
			if a.LUID == luid && a.Name == name {
				if e = files.Write(filepath.Join(id, "probe-adapter"+role+".json"), a); e != nil {
					return e
				}
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(until) {
			return errors.New("probe adapter not visible")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Independent final bound also closes the adapter if both owner and watcher fail.
	remaining := time.Until(p.Deadline.Add(20 * time.Second))
	if remaining > p.Timeout+20*time.Second {
		remaining = p.Timeout + 20*time.Second
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	for {
		var release bool
		if read(files, id, "probe-release"+role+".json", &release) == nil && release {
			return nil
		}
		if e = pump.drain(files, id, role); e != nil {
			return e
		}
		select {
		case <-timer.C:
			return nil
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func nativeProbe(files securefile.AdminStore, id, stage string) error {
	until := time.Now().Add(15 * time.Second)
	var adapter winnet.Adapter
	for {
		if read(files, id, "probe-adapter.json", &adapter) == nil {
			break
		}
		if time.Now().After(until) {
			return errors.New("adapter readiness timeout")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if adapter.Hardware || adapter.Type != 53 {
		return errors.New("unexpected probe adapter type")
	}
	if stage == "native" {
		return exerciseNative(files, id, adapter)
	}
	if stage == "pair" {
		return exercisePair(files, id, adapter)
	}
	if stage == "mutation" {
		return exerciseMutation(files, id, adapter)
	}
	return files.Write(filepath.Join(id, "probe-native.json"), map[string]any{"stage": stage, "adapter_created": true, "network_policy_changed": false})
}

func releaseAdapter(files securefile.AdminStore, id string) error {
	return errors.Join(releaseOneAdapter(files, id, ""), releaseOneAdapter(files, id, "-tun"))
}
func releaseOneAdapter(files securefile.AdminStore, id, role string) error {
	var holder platform.Identity
	e := read(files, id, "probe-holder"+role+".json", &holder)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return fmt.Errorf("read holder %q: %w", role, e)
	}
	if e = files.Write(filepath.Join(id, "probe-release"+role+".json"), true); e != nil {
		return fmt.Errorf("signal holder %q: %w", role, e)
	}
	until := time.Now().Add(15 * time.Second)
	for {
		actual, e := platform.Process(holder.PID)
		if e != nil {
			return fmt.Errorf("query holder %q identity: %w", role, e)
		}
		if actual != holder {
			break
		}
		if time.Now().After(until) {
			return errors.New("adapter holder did not close")
		}
		time.Sleep(100 * time.Millisecond)
	}
	until = time.Now().Add(10 * time.Second)
	for {
		rows, e := winnet.Adapters()
		if e != nil {
			return fmt.Errorf("enumerate adapters after closing holder %q: %w", role, e)
		}
		present := false
		for _, a := range rows {
			if a.Name == "NL-Probe-"+id[len("netlaunch-"):]+role {
				present = true
			}
		}
		if !present {
			return nil
		}
		if time.Now().After(until) {
			return errors.New("probe adapter remains after close")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func exerciseNative(files securefile.AdminStore, id string, a winnet.Adapter) error {
	// Only documentation addresses on this freshly created adapter. No default
	// route, capture half, physical DNS or existing adapter is modified here.
	rows, e := winnet.Routes()
	if e != nil {
		return e
	}
	for _, r := range rows {
		if r.Prefix == "192.0.2.1/32" || r.Prefix == "192.0.2.2/32" {
			return errors.New("fixture address route already exists")
		}
	}
	m := manager(files, id)
	status := map[string]any{"stage": "native", "adapter_created": true}
	record := func(step string, err error) error {
		status[step] = err == nil
		if err != nil {
			status["error"] = err.Error()
		}
		if e := files.Write(filepath.Join(id, "probe-native.json"), status); e != nil {
			return e
		}
		return err
	}
	if _, e = m.EnsureVPNAddress(a, "192.0.2.1"); e != nil {
		return record("address", e)
	}
	if e = record("address", nil); e != nil {
		return e
	}
	r, e := winnet.NewRoute(a, "192.0.2.2/32", "0.0.0.0", 9000)
	if e != nil {
		return e
	}
	if e = record("route", m.EnsureRoute(r)); e != nil {
		return e
	}
	if e = record("address_ready", waitAddress(a)); e != nil {
		return e
	}
	if e = record("tcp_before_guard", tcpProbe(a, 18443)); e != nil {
		return e
	}
	foreign, e := runForeign(files, id)
	if e != nil {
		return record("foreign_before_guard", e)
	}
	if !foreign["connected"] {
		return record("foreign_before_guard", errors.New("control TCP did not connect"))
	}
	if e = record("foreign_before_guard", nil); e != nil {
		return e
	}
	if e = record("udp_before_guard", udpProbe(a)); e != nil {
		return e
	}
	if e = record("ipv6_before_guard", ipv6Probe(a)); e != nil {
		return e
	}
	time.Sleep(200 * time.Millisecond)
	var baseline map[string]int
	if e = read(files, id, "probe-packets.json", &baseline); e != nil {
		return e
	}
	if baseline["udp"] == 0 || baseline["tcp_18445"] == 0 || baseline["tcp6_18446"] == 0 {
		return errors.New("missing unfiltered packet controls")
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	guard, e := winwfp.Prepare(a, exe)
	if e != nil {
		return record("guard_prepare", e)
	}
	if e = record("guard", m.EnsureGuard(guard)); e != nil {
		return e
	}
	if e = record("guard_readback", m.CheckCompanyGuard(guard)); e != nil {
		return e
	}
	if e = record("tcp_with_guard", tcpProbe(a, 18443)); e != nil {
		return e
	}
	foreign, e = runForeign(files, id)
	if e != nil {
		return e
	}
	if foreign["connected"] || !foreign["access_denied"] {
		return record("foreign_blocked", errors.New("foreign TCP was not explicitly denied"))
	}
	if e = record("foreign_blocked", nil); e != nil {
		return e
	}
	e = udpProbe(a)
	var timeout net.Error
	if !errors.Is(e, syscall.Errno(10013)) && !(errors.As(e, &timeout) && timeout.Timeout()) {
		return record("udp_blocked", fmt.Errorf("UDP was not denied or timed out: %v", e))
	}
	if e = record("udp_blocked", nil); e != nil {
		return e
	}
	e = ipv6Probe(a)
	if !errors.Is(e, syscall.Errno(10013)) && !(errors.As(e, &timeout) && timeout.Timeout()) {
		return record("ipv6_blocked", fmt.Errorf("IPv6 was not denied or timed out: %v", e))
	}
	if e = record("ipv6_blocked", nil); e != nil {
		return e
	}
	time.Sleep(200 * time.Millisecond)
	var after map[string]int
	if e = read(files, id, "probe-packets.json", &after); e != nil {
		return e
	}
	if after["udp"] != baseline["udp"] || after["tcp_18445"] != baseline["tcp_18445"] || after["tcp6_18446"] != baseline["tcp6_18446"] {
		return record("blocked_packets_absent", errors.New("blocked traffic reached test adapter"))
	}
	if e = record("blocked_packets_absent", nil); e != nil {
		return e
	}
	// A successful echo after removing only our guard rules rules out a dead
	// UDP fixture as the cause of the preceding timeout and missing packets.
	if e = winwfp.Remove(guard); e != nil {
		return record("guard_remove_control", e)
	}
	if e = record("udp_after_guard_removal", udpProbe(a)); e != nil {
		return e
	}
	if e = record("ipv6_after_guard_removal", ipv6Probe(a)); e != nil {
		return e
	}
	if e = record("guard_reinstalled", m.EnsureGuard(guard)); e != nil {
		return e
	}
	// Save and restore DNS through the production journal, scoped to the new
	// adapter only. The physical adapter's DNS and current VPN remain untouched.
	before, e := winnet.ConfiguredDNS(a)
	if e != nil {
		return record("dns_read", e)
	}
	desired := before
	desired.NameServers = "127.0.0.1"
	if e = record("dns", m.SetDNS(a, desired)); e != nil {
		return e
	}
	status["network_policy_changed"] = true
	return files.Write(filepath.Join(id, "probe-native.json"), status)
}
