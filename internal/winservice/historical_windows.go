//go:build windows

package winservice

import (
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
)

func VerifyHistoricalServicePreparation(profile, runRef, instance, runID, lifecycleSHA, expectedSpecDigest string) (bool, error) {
	return verifyHistoricalPreparationRole(profile, runRef, instance, runID, lifecycleSHA, expectedSpecDigest, false)
}
func VerifyRecoveryHistoricalServicePreparation(profile, runRef, instance, runID, lifecycleSHA, expectedSpecDigest string) (bool, error) {
	return verifyHistoricalPreparationRole(profile, runRef, instance, runID, lifecycleSHA, expectedSpecDigest, true)
}
func verifyHistoricalPreparationRole(profile, runRef, instance, runID, lifecycleSHA, expectedSpecDigest string, recovery bool) (bool, error) {
	current, err := loadEnrolledBindingRole(profile, recovery)
	if err != nil {
		return false, err
	}
	if !releaseText.MatchString(runRef) || !releaseText.MatchString(instance) || !engineRunID.MatchString(runID) || !digestText.MatchString(lifecycleSHA) || (expectedSpecDigest != "" && !digestText.MatchString(expectedSpecDigest)) || current.ServiceInstance != instance {
		return false, errors.New("invalid historical preparation identity")
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return false, err
	}
	root := filepath.Join(base, "LuminaVPN", "ServiceState")
	if err = (WindowsProtectedFiles{Root: root}).validatePath(root); err != nil {
		return false, err
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > 8192 {
		return false, errors.New("historical restoration census unavailable")
	}
	files := installedStateFiles{root: root}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "restoration-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if entry.IsDir() {
			return false, errors.New("unknown restoration census entry")
		}
		id := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "restoration-"), ".json")
		receipt, err := readRestoration(files, id)
		if err != nil {
			return false, err
		}
		source := receipt.Source
		if source.ProfileID != profile || source.OwnerSID != current.OwnerSID || source.ExecutorSID != current.ExecutorSID || source.ServiceInstance != instance || source.RunRef != runRef {
			continue
		}
		if receipt.Scope == "unprepared" && source.PreparedRunID == "" && source.SpecDigest == "" && source.LifecycleSHA256 != "" && source.LifecycleSHA256 == lifecycleSHA {
			var proof struct {
				Retained []string `json:"retained_run_ids"`
			}
			if json.Unmarshal(receipt.Proof, &proof) != nil {
				return false, errors.New("invalid historical retained census")
			}
			for _, retained := range proof.Retained {
				if retained == runID {
					return true, nil
				}
			}
		}
		// The legacy receipt's independent immutable spec digest also binds
		// the old manifest's lifecycle pin. The caller separately verifies
		// the old frozen bytes before calculating this exact digest.
		if source.ProfileID == profile && source.OwnerSID == current.OwnerSID && source.ExecutorSID == current.ExecutorSID && source.ServiceInstance == instance && source.RunRef == runRef && source.PreparedRunID == runID && source.SpecDigest == expectedSpecDigest && (source.LifecycleSHA256 == "" || source.LifecycleSHA256 == lifecycleSHA) && receipt.Scope == "run" {
			return true, nil
		}
	}
	return false, nil
}
