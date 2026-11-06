//go:build windows

package winservice

import (
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"path/filepath"
	"time"
)

type recoveryAcknowledgement struct {
	Version       int       `json:"version"`
	Nonce         string    `json:"nonce"`
	ProfileID     string    `json:"profile_id"`
	RestorationID string    `json:"restoration_id"`
	Clean         bool      `json:"clean"`
	Finished      time.Time `json:"finished_at"`
}

func writeRecoveryAcknowledgement(host *Host, args []string) error {
	if host == nil || host.Broker == nil || len(args) > 2 {
		return errors.New("invalid recovery service request")
	}
	nonce := ""
	if len(args) == 2 {
		nonce = args[1]
		if !releaseText.MatchString(nonce) {
			return errors.New("invalid recovery nonce")
		}
	} else {
		var err error
		nonce, err = newID("recover-")
		if err != nil {
			return err
		}
	}
	enrolled, ok := host.Broker.owners.(interface{ Enrolled() (Binding, error) })
	if !ok {
		return errors.New("recovery enrollment unavailable")
	}
	binding, err := enrolled.Enrolled()
	if err != nil || binding.RunRef != "" || binding.LastRestorationID == "" {
		return errors.New("recovery did not publish an empty restored binding")
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return err
	}
	files := installedStateFiles{root: filepath.Join(base, "LuminaVPN", "ServiceState")}
	receipt, err := readRestoration(files, binding.LastRestorationID)
	if err != nil || !sameEnrollment(binding, receipt.Enrollment) {
		return errors.New("recovery receipt does not match enrolled binding")
	}
	data, err := json.Marshal(recoveryAcknowledgement{Version: 1, Nonce: nonce, ProfileID: binding.ProfileID, RestorationID: binding.LastRestorationID, Clean: true, Finished: time.Now()})
	if err != nil {
		return err
	}
	return files.Write("recovery-ack.json", data)
}
