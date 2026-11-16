//go:build darwin

package app

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"syscall"

	"netlaunch/internal/engine"
	"netlaunch/internal/serviceprotocol"
)

func companyIntentEntry(args []string, output io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("native administrator authorization is required")
	}
	f := flag.NewFlagSet("_company-intent", flag.ContinueOnError)
	f.SetOutput(output)
	run := f.String("run", "", "exact active run directory")
	request := f.String("request-id", "", "company request identity")
	generation := f.Uint64("expected-generation", 0, "current applied channel generation")
	intent := f.String("company", "", "company intent, on or off")
	personal := f.String("expected-personal", "", "unchanged personal channel, on or off")
	device := f.Int64("device", 0, "bound run device")
	inode := f.Uint64("inode", 0, "bound run inode")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *run == "" || (*intent != "on" && *intent != "off") {
		return errors.New("invalid native company intent request")
	}
	if *personal != "" || *device != 0 || *inode != 0 {
		if (*personal != "on" && *personal != "off") || int64(int32(*device)) != *device || *inode == 0 {
			return errors.New("invalid selected macOS run identity")
		}
		return engine.ApplyDarwinDesktopCompany(*run, engine.DarwinDesktopCompanyRequest{
			ID: *request, Generation: *generation, Company: *intent == "on", Personal: *personal == "on",
			Device: int32(*device), Inode: *inode,
		})
	}
	return engine.RequestDarwinCompanyChange(*run, *request, *generation, *intent == "on")
}

func (r *RunStop) SetMacCompany(ctx context.Context, id string, generation uint64, company, personal bool) error {
	if !serviceprotocol.ValidID(id) {
		return errors.New("invalid desktop company request identity")
	}
	if err := r.checkMacCompany(ctx, generation); err != nil {
		return err
	}
	native, ok := r.identity.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("selected macOS run identity is unavailable")
	}
	name := engine.DarwinCompanyPermitName(id)
	permit, err := r.dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer r.dir.Remove(name)
	defer permit.Close()
	if err := syscall.Flock(int(permit.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return err
	}
	return engine.LaunchDarwinDesktopCompany(ctx, r.path, engine.DarwinDesktopCompanyRequest{
		ID: id, Generation: generation, Company: company, Personal: personal, Device: native.Dev, Inode: native.Ino,
	})
}
