//go:build windows

package winservice

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
	p "netlaunch/internal/serviceprotocol"
)

type ClientSettingsStore struct {
	mu      sync.Mutex
	files   protectedStateFiles
	binding Binding
}
type installedPreferences struct {
	Version     int    `json:"version"`
	ProfileID   string `json:"profile_id"`
	Environment string `json:"environment"`
	AutoConnect bool   `json:"auto_connect"`
}

func OpenClientSettingsStore(binding Binding) (*ClientSettingsStore, error) {
	current, err := loadEnrolledBinding(binding.ProfileID)
	if err != nil || !sameEnrollment(current, binding) {
		return nil, errors.New("settings enrollment unavailable")
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, err
	}
	return &ClientSettingsStore{files: installedStateFiles{root: filepath.Join(base, "LuminaVPN", "ServiceState")}, binding: binding}, nil
}
func (s *ClientSettingsStore) Load() (p.SettingsPayload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.files.Read("preferences-" + s.binding.ProfileID + ".json")
	if errors.Is(err, errProtectedStateMissing) {
		return p.SettingsPayload{Environment: "home"}, nil
	}
	if err != nil {
		return p.SettingsPayload{}, err
	}
	var stored installedPreferences
	if decodeState(data, &stored) != nil || stored.Version != 1 || stored.ProfileID != s.binding.ProfileID || stored.AutoConnect || (stored.Environment != "home" && stored.Environment != "office") {
		return p.SettingsPayload{}, errors.New("invalid installed preferences")
	}
	return p.SettingsPayload{Environment: stored.Environment, AutoConnect: false}, nil
}
func (s *ClientSettingsStore) Save(settings p.SettingsPayload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if settings.AutoConnect || (settings.Environment != "home" && settings.Environment != "office") {
		return errors.New("unsupported startup preference")
	}
	data, err := json.Marshal(installedPreferences{Version: 1, ProfileID: s.binding.ProfileID, Environment: settings.Environment})
	if err != nil {
		return err
	}
	return s.files.Write("preferences-"+s.binding.ProfileID+".json", data)
}
