//go:build darwin

package app

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"netlaunch/internal/engine"
	"netlaunch/internal/serviceprotocol"
)

func personalIntentEntry(args []string, output io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("native administrator authorization is required")
	}
	f := flag.NewFlagSet("_personal-intent", flag.ContinueOnError)
	f.SetOutput(output)
	run := f.String("run", "", "exact active run directory")
	request := f.String("request-id", "", "personal request identity")
	generation := f.Uint64("expected-generation", 0, "current applied channel generation")
	personal := f.String("personal", "", "personal intent, on or off")
	company := f.String("expected-company", "", "unchanged company channel, on or off")
	device := f.Int64("device", 0, "bound run device")
	inode := f.Uint64("inode", 0, "bound run inode")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *run == "" || (*personal != "on" && *personal != "off") ||
		(*company != "on" && *company != "off") || int64(int32(*device)) != *device || *inode == 0 {
		return errors.New("invalid native personal intent request")
	}
	return engine.ApplyDarwinDesktopPersonal(*run, engine.DarwinDesktopPersonalRequest{
		ID: *request, Generation: *generation, Company: *company == "on", Personal: *personal == "on",
		Device: int32(*device), Inode: *inode,
	})
}

func (r *RunStop) SetMacPersonal(ctx context.Context, id string, generation uint64, company, personal bool) error {
	if !serviceprotocol.ValidID(id) {
		return errors.New("invalid desktop personal request identity")
	}
	status, err := r.checkMacChannelGeneration(ctx, generation)
	if err != nil {
		return err
	}
	if !status.DarwinPersonalControl {
		return errors.New("selected macOS personal channel is unavailable")
	}
	return r.withMacChannelPermit(engine.DarwinPersonalPermitName(id), func(device int32, inode uint64) error {
		return engine.LaunchDarwinDesktopPersonal(ctx, r.path, engine.DarwinDesktopPersonalRequest{
			ID: id, Generation: generation, Company: company, Personal: personal, Device: device, Inode: inode,
		})
	})
}
