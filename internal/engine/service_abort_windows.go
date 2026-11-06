//go:build windows

package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
	"netlaunch/internal/winservice"
)

type ServicePreparationAbortProof struct {
	Clean                  bool      `json:"clean"`
	NeverBound             bool      `json:"never_bound"`
	IdentityCensusComplete bool      `json:"identity_census_complete"`
	NeverServed            bool      `json:"never_served"`
	PreparedOnly           bool      `json:"prepared_only"`
	RetainedRunIDs         []string  `json:"retained_run_ids"`
	Errors                 []string  `json:"errors"`
	StartedAt              time.Time `json:"started_at"`
	FinishedAt             time.Time `json:"finished_at"`
}

type servicePreparationClaim struct {
	Version int `json:"version"`
	ServicePreparationReference
	RunID           string `json:"run_id"`
	ExecutorSID     string `json:"executor_sid"`
	LifecycleSHA256 string `json:"lifecycle_sha256"`
}

type ServicePreparationHistoryVerifier func(ServicePreparationReference, string, string, string) (bool, error)

func partitionPreparationClaim(claim servicePreparationClaim, runID string, current ServicePreparationReference, currentSHA string) (bool, error) {
	if claim.Version != 1 || claim.ServicePreparationReference.Validate() != nil || claim.ProfileID != current.ProfileID || claim.RunID != runID || !serviceRunID.MatchString(runID) || claim.ExecutorSID != "S-1-5-18" || !serviceDigest.MatchString(claim.LifecycleSHA256) {
		return false, errors.New("run preparation claim is missing or unknown")
	}
	matching := claim.ServicePreparationReference == current
	if matching && claim.LifecycleSHA256 != currentSHA {
		return false, errors.New("current preparation differs from protected release")
	}
	return matching, nil
}

func historicalPreparationSourceDigest(claim servicePreparationClaim, manifestBytes, lifecycleBytes []byte) (string, error) {
	if len(lifecycleBytes) != 0 {
		sum := sha256.Sum256(lifecycleBytes)
		if hex.EncodeToString(sum[:]) != claim.LifecycleSHA256 {
			return "", errors.New("historical frozen helper differs from its own preparation claim")
		}
	}
	if len(manifestBytes) == 0 {
		// Only an independently published unprepared receipt with its own
		// nonempty lifecycle pin may establish an early, manifest-less claim.
		return "", nil
	}
	var manifest Manifest
	if decodeServicePreparation(manifestBytes, &manifest) != nil || manifest.Version != 1 || manifest.OwnerSID != "S-1-5-18" || manifest.Service == nil || manifest.Service.ExecutorSID != "S-1-5-18" || preparationReference(*manifest.Service) != claim.ServicePreparationReference || manifest.Service.LifecycleSHA256 != claim.LifecycleSHA256 || len(lifecycleBytes) == 0 {
		return "", errors.New("historical preparation source cannot be verified")
	}
	return runSpecDigest(immutableRunSpec(manifest)), nil
}

func verifyHistoricalPreparationEvidence(claim servicePreparationClaim, manifest, image []byte, verify ServicePreparationHistoryVerifier) error {
	digest, err := historicalPreparationSourceDigest(claim, manifest, image)
	if err != nil {
		return err
	}
	if verify == nil {
		return errors.New("historical strict restoration verifier unavailable")
	}
	verified, err := verify(claim.ServicePreparationReference, claim.RunID, claim.LifecycleSHA256, digest)
	if err != nil || !verified {
		return errors.New("historical preparation has no matching strict restoration receipt")
	}
	return nil
}

func historicalPreparationSource(run string, claim servicePreparationClaim, verify ServicePreparationHistoryVerifier) error {
	manifest, err := securefile.Read(filepath.Join(run, "manifest.json"), 1<<20, true)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	image, err := securefile.Read(filepath.Join(run, "netlaunch.exe"), 128<<20, true)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return verifyHistoricalPreparationEvidence(claim, manifest, image, verify)
}

func preparationReference(b ServiceRunBinding) ServicePreparationReference {
	return ServicePreparationReference{ProfileID: b.ProfileID, BindingRunRef: b.RunRef, ServiceInstance: b.ServiceInstance}
}

func verifyServicePreparedStartBinding(m Manifest, runID string, b winservice.Binding) error {
	if m.Service == nil || b.ProfileID != m.Service.ProfileID || b.RunRef != m.Service.RunRef || b.ServiceInstance != m.Service.ServiceInstance || b.ExecutorSID != "S-1-5-18" || b.PreparedRunID != runID || b.SpecDigest != runSpecDigest(immutableRunSpec(m)) {
		return errors.New("native service start requires the exact durable prepared binding")
	}
	return nil
}

func verifyServicePreparedNativeStart(run string, m Manifest) error {
	if m.Service == nil {
		return nil
	}
	binding, err := winservice.LoadPreparedBinding(m.Service.ProfileID)
	if err != nil {
		return err
	}
	if err = verifyServicePreparedStartBinding(m, filepath.Base(run), binding); err != nil {
		return err
	}
	return servicePreparationNotAborted(filepath.Dir(run), preparationReference(*m.Service))
}

func preparationAbortName(r ServicePreparationReference) string {
	return "abort-" + serviceHash(r) + ".json"
}

func servicePreparationNotAborted(profile string, r ServicePreparationReference) error {
	if _, err := securefile.Read(filepath.Join(profile, preparationAbortName(r)), 4096, true); !errors.Is(err, os.ErrNotExist) {
		return errors.New("service preparation was stopped or its stop marker cannot be verified")
	}
	return nil
}

func decodeServicePreparation(data []byte, target any) error {
	if len(data) == 0 || len(data) > 1<<20 {
		return errors.New("invalid preparation metadata size")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return errors.New("invalid preparation metadata")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("multiple preparation metadata values")
	}
	return nil
}

type servicePreparationEvidence struct {
	RunID, Problem string
	MatchingClaim  bool
	AdminAbsent    bool
}

func preparationCensusProof(rows []servicePreparationEvidence, unknown []string) ServicePreparationAbortProof {
	p := ServicePreparationAbortProof{NeverBound: true, IdentityCensusComplete: len(unknown) == 0, NeverServed: true, PreparedOnly: true, RetainedRunIDs: []string{}, Errors: append([]string{}, unknown...)}
	for _, row := range rows {
		if row.Problem != "" {
			p.IdentityCensusComplete = false
			p.Errors = append(p.Errors, row.Problem)
		}
		if !row.MatchingClaim {
			continue
		}
		p.RetainedRunIDs = append(p.RetainedRunIDs, row.RunID)
		if !row.AdminAbsent {
			p.NeverServed, p.PreparedOnly = false, false
			p.Errors = append(p.Errors, "private administrator run exists or absence is unknown")
		}
	}
	p.Clean = p.NeverBound && p.IdentityCensusComplete && p.NeverServed && p.PreparedOnly && len(p.Errors) == 0
	return p
}

func preparationAllowedPaths(runtime runtimebundle.Manifest) (map[string]bool, error) {
	if runtime.Version != 1 || runtime.OS != "windows" || runtime.Arch != "amd64" || len(runtime.Files) != 18 {
		return nil, errors.New("protected runtime manifest required for preparation census")
	}
	allowed := map[string]bool{"preparation.json": false, "manifest.json": false, "nodes.json": false, "netlaunch.exe": false, "auth.json": false, "runtime": true, "runtime/manifest.json": false}
	for _, file := range runtime.Files {
		if !fs.ValidPath(file.Path) || strings.ContainsAny(file.Path, `\:`) || path.Clean(file.Path) != file.Path || !serviceDigest.MatchString(file.SHA256) {
			return nil, errors.New("invalid protected runtime census path")
		}
		name := "runtime/" + file.Path
		if _, exists := allowed[name]; exists {
			return nil, errors.New("duplicate protected runtime census path")
		}
		allowed[name] = false
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			allowed[dir] = true
		}
	}
	return allowed, nil
}

func verifyPreparationMaterials(run string, allowed map[string]bool) error {
	count := 0
	return filepath.WalkDir(run, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == run {
			return nil
		}
		count++
		if count > 128 {
			return errors.New("preparation material census limit exceeded")
		}
		relative, err := filepath.Rel(run, name)
		if err != nil {
			return err
		}
		dir, known := allowed[filepath.ToSlash(relative)]
		if !known || dir != entry.IsDir() {
			return errors.New("unknown preparation material retained")
		}
		return securefile.CheckPrivate(name, dir)
	})
}

// AbortServicePreparation is called only after the helper independently reads
// an exact, durably unprepared binding and the broker has joined its worker.
// It retains partial files. A fixed stop marker prevents later preparation or
// serve, and any private administrator material makes the proof incomplete.
func AbortServicePreparation(r ServicePreparationReference, lifecycleSHA string, runtime runtimebundle.Manifest, verifyHistory ServicePreparationHistoryVerifier) (ServicePreparationAbortProof, error) {
	started := time.Now()
	fail := func(err error) (ServicePreparationAbortProof, error) {
		return ServicePreparationAbortProof{Errors: []string{err.Error()}, RetainedRunIDs: []string{}, StartedAt: started, FinishedAt: time.Now()}, err
	}
	if err := requireServiceSystem(); err != nil {
		return fail(err)
	}
	if err := r.Validate(); err != nil {
		return fail(err)
	}
	if !serviceDigest.MatchString(lifecycleSHA) {
		return fail(errors.New("protected lifecycle pin required"))
	}
	allowed, err := preparationAllowedPaths(runtime)
	if err != nil {
		return fail(err)
	}
	root, err := serviceDataRoot()
	if err != nil {
		return fail(err)
	}
	if err = securefile.CheckDir(root); err != nil {
		return fail(err)
	}
	runs := filepath.Join(root, "runs")
	if err = securefile.CheckDir(runs); err != nil {
		return fail(err)
	}
	profile := filepath.Join(runs, r.ProfileID)
	if err = securefile.Dir(profile); err != nil {
		return fail(err)
	}
	unlock, err := securefile.Lock(filepath.Join(profile, "prepare.lock"), 10*time.Second)
	if err != nil {
		return fail(err)
	}
	defer unlock()
	if err = securefile.Write(filepath.Join(profile, preparationAbortName(r)), r); err != nil {
		return fail(err)
	}
	entries, err := os.ReadDir(profile)
	if err != nil {
		return fail(err)
	}
	if len(entries) > 4096 {
		return fail(errors.New("preparation census limit exceeded"))
	}
	admin, err := securefile.OpenAdminStore()
	if err != nil {
		return fail(err)
	}
	rows := []servicePreparationEvidence{}
	unknown := []string{}
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(profile, name)
		if name == "prepare.lock" {
			if err = securefile.CheckPrivate(path, false); err != nil {
				unknown = append(unknown, "preparation lock cannot be verified")
			}
			continue
		}
		if strings.HasPrefix(name, "abort-") && strings.HasSuffix(name, ".json") {
			var prior ServicePreparationReference
			data, readErr := securefile.Read(path, 4096, true)
			if readErr != nil || decodeServicePreparation(data, &prior) != nil || prior.Validate() != nil || prior.ProfileID != r.ProfileID || preparationAbortName(prior) != name {
				unknown = append(unknown, "unverified preparation stop marker")
			}
			continue
		}
		row := servicePreparationEvidence{RunID: name}
		if !serviceRunID.MatchString(name) || !entry.IsDir() || securefile.CheckPrivate(path, true) != nil {
			unknown = append(unknown, "unknown or unprotected preparation material")
			continue
		}
		var claim servicePreparationClaim
		data, readErr := securefile.Read(filepath.Join(path, "preparation.json"), 4096, true)
		if readErr != nil || decodeServicePreparation(data, &claim) != nil {
			row.Problem = "run preparation claim is missing or unknown"
			rows = append(rows, row)
			continue
		}
		row.MatchingClaim, err = partitionPreparationClaim(claim, name, r, lifecycleSHA)
		if err != nil {
			row.Problem = err.Error()
			rows = append(rows, row)
			continue
		}
		if !row.MatchingClaim {
			if sourceErr := historicalPreparationSource(path, claim, verifyHistory); sourceErr != nil {
				row.Problem = "historical preparation has no matching protected source and strict restoration receipt"
			}
			rows = append(rows, row)
			continue
		}
		if err = verifyPreparationMaterials(path, allowed); err != nil {
			row.Problem = "unknown, unprotected or unreadable partial preparation material"
		}
		manifestData, readErr := securefile.Read(filepath.Join(path, "manifest.json"), 1<<20, true)
		if readErr == nil {
			var m Manifest
			if json.Unmarshal(manifestData, &m) != nil || m.Version != 1 || m.OwnerSID != "S-1-5-18" || m.Service == nil || preparationReference(*m.Service) != r || m.Service.ExecutorSID != "S-1-5-18" || m.Service.LifecycleSHA256 != lifecycleSHA {
				row.Problem = "partial manifest identity cannot be verified"
			}
		} else if !errors.Is(readErr, os.ErrNotExist) {
			row.Problem = "partial manifest cannot be read"
		}
		row.AdminAbsent = errors.Is(admin.Check(name, true), os.ErrNotExist)
		rows = append(rows, row)
	}
	proof := preparationCensusProof(rows, unknown)
	proof.StartedAt, proof.FinishedAt = started, time.Now()
	if proof.FinishedAt.Sub(started) > 10*time.Second {
		proof.Clean, proof.IdentityCensusComplete = false, false
		proof.Errors = append(proof.Errors, "preparation census exceeded deadline")
	}
	if !proof.Clean {
		return proof, errors.New("preparation abort proof incomplete; retain materials")
	}
	return proof, nil
}
