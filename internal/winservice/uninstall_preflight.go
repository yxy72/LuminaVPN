package winservice

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io/fs"
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
var errLegacyRegistryValueMissing = errors.New("legacy registry value absent")

type legacyRegistryKey interface {
	StringValue(string) (string, error)
	Close() error
}

// OpenMachine validates an existing authority's leaf and ancestor replacement
// rights. Absence is an observation, not a reservation: the nonce-bound native
// resume entry claims the two product leaves before NSIS uses or writes them.
type legacyRegistry interface {
	OpenMachine(uint32, string) (legacyRegistryKey, error)
	ProbeMachine(uint32, string) (bool, error)
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
		present, err := registry.ProbeMachine(view, legacyUninstallPrefix+alias)
		if err != nil {
			return err
		}
		if present {
			return errors.New("unknown legacy machine registration")
		}
	}
	// The x64 installer never consumes the 32-bit view, even if a key appears
	// after this conflict probe. Its absence carries no executable authority.
	if view == 0x200 {
		for _, path := range []string{installPath, legacyUninstallPrefix + id} {
			present, err := registry.ProbeMachine(view, path)
			if err != nil {
				return err
			}
			if present {
				return errors.New("32-bit legacy machine registration requires removal before this x64 installer")
			}
		}
		return nil
	}
	install, installErr := registry.OpenMachine(view, installPath)
	if installErr == nil {
		defer func() { result = errors.Join(result, install.Close()) }()
	}
	uninstall, uninstallErr := registry.OpenMachine(view, legacyUninstallPrefix+id)
	if uninstallErr == nil {
		defer func() { result = errors.Join(result, uninstall.Close()) }()
	}
	if (installErr != nil && !errors.Is(installErr, errLegacyRegistryMissing)) || (uninstallErr != nil && !errors.Is(uninstallErr, errLegacyRegistryMissing)) {
		return errors.New("incomplete or untrusted legacy machine registration")
	}
	// electron-builder 26.18 writes these values to two different keys.
	location, hasLocation, locationErr := optionalLegacyValue(install, "InstallLocation")
	command, hasCommand, commandErr := optionalLegacyValue(uninstall, "UninstallString")
	if locationErr != nil || commandErr != nil || hasLocation != hasCommand || (hasLocation && !fixedUninstallString(root, location, command)) {
		return errors.New("unknown legacy uninstall target or parameters")
	}
	// Old protected uninstallers also consume these values for shortcut deletion.
	// Limit supported legacy metadata to this product's fixed flat shortcuts.
	for name, expected := range map[string]string{"ShortcutName": "LuminaVPN", "MenuDirectory": ""} {
		value, present, err := optionalLegacyValue(install, name)
		if err != nil || (present && value != expected) {
			return errors.New("unknown legacy shortcut location")
		}
	}
	err := fileCheck(filepath.Join(root, "Uninstall LuminaVPN.exe"))
	if errors.Is(err, fs.ErrNotExist) && !hasCommand {
		return nil // Fresh install or interrupted empty product-key reservation.
	}
	return err
}

func optionalLegacyValue(key legacyRegistryKey, name string) (string, bool, error) {
	if key == nil {
		return "", false, nil
	}
	value, err := key.StringValue(name)
	if errors.Is(err, errLegacyRegistryValueMissing) {
		return "", false, nil
	}
	return value, err == nil, err
}

func missingLegacyImagePreflight(journal installJournal, exists bool, err error) error {
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if validateInstallJournal(journal) != nil || journal.Action != "retire" || journal.Phase != "complete" {
		return errors.New("existing service state requires its protected previous uninstaller")
	}
	return nil
}
func InstallPlanExitCode(plan InstallPlan, err error) int {
	if err != nil || (plan.TargetPreflight != "absent" && plan.TargetPreflight != "protected") {
		return 1
	}
	return 0
}
