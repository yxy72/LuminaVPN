package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
)

const darwinServicePlist = "/Library/LaunchDaemons/" + darwinServiceLabel + ".plist"

func MacServiceCommand(args []string) (bool, error) {
	if len(args) == 0 || args[0] != "_mac-service-install" && args[0] != "_mac-service" {
		return false, nil
	}
	if len(args) < 2 || os.Geteuid() != 0 {
		return true, errors.New("macOS network service requires administrator authorization")
	}
	uid, err := strconv.Atoi(args[1])
	if err != nil || uid <= 0 {
		return true, errors.New("invalid macOS network service account")
	}
	switch args[0] {
	case "_mac-service":
		if len(args) == 2 {
			return true, serveDarwinDesktopService(uid)
		}
	case "_mac-service-install":
		if len(args) == 3 && filepath.IsAbs(args[2]) {
			return true, installDarwinService(uid, args[2])
		}
	}
	return true, errors.New("invalid macOS network service command")
}

func authorizeDarwinService(ctx context.Context, bundle string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return runDarwinAuthorization(ctx, "umask 077; cd /private/tmp && "+shellQuote(executable)+
		" _mac-service-install "+strconv.Itoa(os.Getuid())+" "+shellQuote(bundle))
}

func checkDarwinServiceDir(path string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return errors.New("macOS network service directory is not administrator controlled")
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func makeDarwinServiceDir(path string) error {
	if path != darwinServiceRoot && !strings.HasPrefix(path, darwinServiceRoot+"/") {
		return checkDarwinServiceDir(path)
	}
	if err := makeDarwinServiceDir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0711); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := checkDarwinServiceDir(path); err != nil {
		return err
	}
	// launchd and the installer run with umask 077. The desktop needs to
	// traverse these directories to reach its socket and its own run.
	return os.Chmod(path, 0711)
}

func installDarwinService(uid int, bundle string) error {
	if err := makeDarwinServiceDir(darwinServiceRoot); err != nil {
		return err
	}
	if err := checkDarwinServiceDir(filepath.Dir(darwinServicePlist)); err != nil {
		return err
	}
	dir := darwinStateRoot
	if err := checkDarwinServiceDir(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := securefile.Dir(dir); err != nil {
		return err
	}
	if err := checkDarwinServiceDir(dir); err != nil {
		return err
	}
	unlock, err := securefile.Lock(filepath.Join(dir, "active.lock"), 0)
	if err != nil {
		return errors.New("stop the active LuminaVPN connection before updating its network service")
	}
	defer unlock()
	if err := requireNoDarwinServiceOwner(dir); err != nil {
		return err
	}

	builds := filepath.Join(darwinServiceRoot, "builds")
	if err := makeDarwinServiceDir(builds); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(builds, "release-")
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(stage)
		}
	}()
	self, err := os.Executable()
	if err != nil {
		return err
	}
	target := filepath.Join(stage, "netlaunch")
	if err := copyExecutable(self, target); err != nil {
		return err
	}
	if err := runtimebundle.Copy(bundle, filepath.Join(stage, "runtime")); err != nil {
		return err
	}
	if err := requireDarwinReloadCore(filepath.Join(stage, "runtime")); err != nil {
		return err
	}
	if err := installDarwinServiceLaunchd(target, uid); err != nil {
		// A failed readback can occur after launchd accepted the job. Preserve
		// the frozen executable until the next explicit installation.
		keep = true
		return err
	}
	keep = true
	return nil
}

func requireNoDarwinServiceOwner(dir string) error {
	if _, err := os.Lstat(filepath.Join(dir, darwinOwnerFile)); !errors.Is(err, os.ErrNotExist) {
		return errors.New("complete the previous LuminaVPN recovery before updating its network service")
	}
	return nil
}

func launchctlDarwinService(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/bin/launchctl", args...).Run()
}

func installDarwinServiceLaunchd(target string, uid int) error {
	const job = "system/" + darwinServiceLabel
	previous, err := securefile.Read(darwinServicePlist, 32<<10, false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	loaded := launchctlDarwinService("print", job) == nil
	if loaded {
		if len(previous) == 0 {
			return errors.New("existing macOS network service registration is unavailable")
		}
		if err := launchctlDarwinService("bootout", job); err != nil {
			return err
		}
	}
	// The fixed path contains only constants and an os.MkdirTemp suffix.
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>%s</string><string>_mac-service</string><string>%d</string></array>
<key>KeepAlive</key><true/>
<key>Umask</key><integer>63</integer>
</dict></plist>
`, darwinServiceLabel, target, uid)
	err = writeDarwinServicePlist([]byte(plist))
	if err == nil {
		err = launchctlDarwinService("bootstrap", "system", darwinServicePlist)
	}
	if err != nil {
		if len(previous) != 0 {
			if writeDarwinServicePlist(previous) == nil && loaded {
				_ = launchctlDarwinService("bootstrap", "system", darwinServicePlist)
			}
		} else {
			_ = os.Remove(darwinServicePlist)
		}
		return errors.New("macOS network service registration did not complete")
	}
	return nil
}

func writeDarwinServicePlist(contents []byte) error {
	f, err := os.CreateTemp(filepath.Dir(darwinServicePlist), ".lumina-network-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(contents)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), darwinServicePlist)
}
