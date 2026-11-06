package winservice

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
)

// This UUID is electron-builder's documented/local implementation identifier,
// not an executable authority. SHA-1 here is UUID-v5 name derivation only.
func luminaUninstallID() string {
	namespace, _ := hex.DecodeString("50e065bc313411e69bab38c9862bdaf3")
	sum := sha1.Sum(append(namespace, []byte("app.luminavpn.desktop")...))
	id := sum[:16]
	id[6] = id[6]&15 | 80
	id[8] = id[8]&63 | 128
	raw := hex.EncodeToString(id)
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:]
}
func fixedUninstallString(root, location, command string) bool {
	return strings.EqualFold(location, root) && strings.EqualFold(command, "\""+strings.TrimRight(root, `\/`)+`\Uninstall LuminaVPN.exe" /allusers`)
}

const legacyUninstallPrefix = `Software\Microsoft\Windows\CurrentVersion\Uninstall\`

var errLegacyRegistryMissing = errors.New("legacy registry key absent")

type legacyRegistryKey interface {
	StringValue(string) (string, error)
	Close() error
}

// OpenMachine validates the opened key and every ancestor, including the
// protected parent of an absent key. No caller-provided key or hive is accepted.
type legacyRegistry interface {
	OpenMachine(uint32, string) (legacyRegistryKey, error)
	HasCurrentUserKey(uint32, string) (bool, error)
}

func checkLegacyUninstall(root string, registry legacyRegistry, fileCheck func(string) error) error {
	for _, view := range []uint32{0x100, 0x200} { // WOW64_64KEY, WOW64_32KEY.
		if err := checkLegacyUninstallView(root, registry, fileCheck, view); err != nil {
			return err
		}
	}
	return nil
}

func checkLegacyUninstallView(root string, registry legacyRegistry, fileCheck func(string) error, view uint32) (result error) {
	id := luminaUninstallID()
	installPath := `Software\` + id
	for _, path := range []string{installPath, legacyUninstallPrefix + id, legacyUninstallPrefix + "{" + id + "}", legacyUninstallPrefix + "app.luminavpn.desktop"} {
		present, err := registry.HasCurrentUserKey(view, path)
		if err != nil {
			return err
		}
		if present {
			return errors.New("legacy per-user registration is not a machine installer authority")
		}
	}
	// Only the fixed builder's UUID key is supported. Unknown aliases must not
	// silently coexist with a machine registration that NSIS will execute.
	for _, alias := range []string{"{" + id + "}", "app.luminavpn.desktop"} {
		key, err := registry.OpenMachine(view, legacyUninstallPrefix+alias)
		if err == nil {
			_ = key.Close()
			return errors.New("unknown legacy machine registration")
		}
		if !errors.Is(err, errLegacyRegistryMissing) {
			return err
		}
	}
	install, installErr := registry.OpenMachine(view, installPath)
	if installErr == nil {
		defer func() { result = errors.Join(result, install.Close()) }()
	}
	uninstall, uninstallErr := registry.OpenMachine(view, legacyUninstallPrefix+id)
	if uninstallErr == nil {
		defer func() { result = errors.Join(result, uninstall.Close()) }()
	}
	if errors.Is(installErr, errLegacyRegistryMissing) && errors.Is(uninstallErr, errLegacyRegistryMissing) {
		return nil
	}
	// The fixed x64 NSIS installer reads only its 64-bit machine view when
	// uninstalling an earlier version. Inspect the 32-bit view for conflicts,
	// but never accept a registration the installer would silently skip.
	if view == 0x200 {
		return errors.New("32-bit legacy machine registration requires removal before this x64 installer")
	}
	if installErr != nil || uninstallErr != nil {
		return errors.New("incomplete or untrusted legacy machine registration")
	}
	// electron-builder 26.18 writes these values to two different keys.
	location, locationErr := install.StringValue("InstallLocation")
	command, commandErr := uninstall.StringValue("UninstallString")
	if locationErr != nil || commandErr != nil || !fixedUninstallString(root, location, command) {
		return errors.New("unknown legacy uninstall target or parameters")
	}
	return fileCheck(filepath.Join(root, "Uninstall LuminaVPN.exe"))
}
func InstallPlanExitCode(plan InstallPlan, err error) int {
	if err != nil || (plan.TargetPreflight != "absent" && plan.TargetPreflight != "protected") {
		return 1
	}
	return 0
}
