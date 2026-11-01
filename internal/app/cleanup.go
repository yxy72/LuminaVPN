package app

import (
	"errors"
	"flag"
	"path/filepath"
	"time"

	"netlaunch/internal/engine"
	"netlaunch/internal/securefile"
)

func (c CLI) cleanup(args []string) error {
	if len(args) == 0 || args[0] != "cleanup" {
		return errors.New("use runs cleanup --profile DIR --run DIR [--apply]; administrator terminal required")
	}
	fs := flag.NewFlagSet("runs cleanup", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	var profile, run string
	var apply bool
	fs.StringVar(&profile, "profile", "", "explicit owner profile")
	fs.StringVar(&run, "run", "", "one historical run under the profile runs directory")
	fs.BoolVar(&apply, "apply", false, "delete eligible payloads; default only previews")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || profile == "" || run == "" {
		return errors.New("cleanup requires --profile and --run")
	}
	profile, err := filepath.Abs(profile)
	if err != nil {
		return err
	}
	run, err = filepath.Abs(run)
	if err != nil {
		return err
	}
	if err := securefile.CheckDir(profile); err != nil {
		return err
	}
	unlock, err := cleanupProfileLock(filepath.Join(profile, "launch.lock"), time.Second)
	if err != nil {
		return err
	}
	defer unlock()
	if err := requireCompleteConfigTransaction(profile); err != nil {
		return err
	}
	result, err := engine.CleanupRun(profile, run, apply)
	if err != nil {
		return err
	}
	return c.json(result)
}
