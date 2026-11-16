//go:build darwin

package engine

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"netlaunch/internal/policy"
)

func TestDarwinDesktopCompanyPermitRequiresLiveLock(t *testing.T) {
	run := t.TempDir()
	name := filepath.Join(run, DarwinCompanyPermitName("change"))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if darwinCompanyPermit(run, "change") {
		t.Fatal("stale permit accepted without a live holder")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if !darwinCompanyPermit(run, "change") {
		t.Fatal("live permit was rejected")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if darwinCompanyPermit(run, "change") {
		t.Fatal("permit remained active after its holder exited")
	}
}

func TestDarwinCompanyDesktopReadbackRequiresExactAppliedRequest(t *testing.T) {
	intent := policy.ChannelIntent{Personal: true}
	s := State{
		TakeoverActive: true, DesiredChannels: &intent, AppliedChannels: &intent,
		ChannelGeneration: 12, AppliedGeneration: 12,
		DarwinCompany: &darwinCompanyControl{
			RequestID: "change", RequestGeneration: 11, DesktopBound: true,
		},
	}
	r := DarwinDesktopCompanyRequest{ID: "change", Generation: 11, Personal: true}
	if got, err := darwinDesktopCompanyApplied(s, r); !got || err != nil {
		t.Fatalf("exact generation readback: %t %v", got, err)
	}
	s.DarwinCompany.Pending = true
	if got, err := darwinDesktopCompanyApplied(s, r); got || err != nil {
		t.Fatalf("pending change was treated as applied: %t %v", got, err)
	}
	s.DarwinCompany.Pending = false
	s.AppliedGeneration = 11
	if got, err := darwinDesktopCompanyApplied(s, r); got || err == nil {
		t.Fatalf("unconfirmed generation was treated as applied: %t %v", got, err)
	}
	s.AppliedGeneration = 12
	r.ID = "other"
	if got, err := darwinDesktopCompanyApplied(s, r); got || err == nil {
		t.Fatalf("unrelated action was treated as applied: %t %v", got, err)
	}
}
