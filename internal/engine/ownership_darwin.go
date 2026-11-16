//go:build darwin

package engine

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"netlaunch/internal/platform"
	"netlaunch/internal/securefile"
)

const darwinOwnerFile = "active-owner.json"
const darwinRecoveryFile = "recovery-proof.json"

type darwinRunOwner struct {
	Version int               `json:"version"`
	Run     string            `json:"run"`
	UID     uint32            `json:"uid"`
	Device  int32             `json:"device"`
	Inode   uint64            `json:"inode"`
	Spec    string            `json:"run_spec_digest"`
	Runner  platform.Identity `json:"runner"`
}

type darwinRecoveryProof struct {
	Version    int            `json:"version"`
	Owner      darwinRunOwner `json:"owner"`
	RestoredAt time.Time      `json:"restored_at"`
}

type darwinOwnershipStore struct {
	root string
	uid  uint32
}

func checkDarwinAdminObject(path string, uid uint32, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || info.Mode().Perm()&0077 != 0 || info.IsDir() != directory ||
		(!directory && !info.Mode().IsRegular()) {
		return errors.New("administrator recovery object is not private and trusted")
	}
	return nil
}

func openDarwinOwnershipStore(run string) (darwinOwnershipStore, error) {
	store := darwinOwnershipStore{root: filepath.Dir(private(run)), uid: 0}
	if os.Geteuid() != 0 {
		return store, errors.New("native administrator authorization is required")
	}
	return store, checkDarwinAdminObject(store.root, store.uid, true)
}

func (store darwinOwnershipStore) lock() (func(), error) {
	if err := checkDarwinAdminObject(store.root, store.uid, true); err != nil {
		return nil, err
	}
	return securefile.Lock(filepath.Join(store.root, "ownership.lock"), time.Second)
}

func readDarwinAdminJSON(path string, uid uint32, value any) error {
	if err := checkDarwinAdminObject(path, uid, false); err != nil {
		return err
	}
	raw, err := securefile.Read(path, 32<<10, true)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(value); err != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid administrator recovery record")
	}
	return nil
}

func syncDarwinDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validDarwinRunPath(run string) bool {
	return filepath.IsAbs(run) && filepath.Clean(run) == run && strings.HasPrefix(filepath.Base(run), "netlaunch-")
}

func (owner darwinRunOwner) valid() bool {
	digest, err := hex.DecodeString(owner.Spec)
	return owner.Version == 1 && validDarwinRunPath(owner.Run) && owner.UID > 0 && owner.Inode != 0 &&
		err == nil && len(digest) == 32 &&
		owner.Runner.PID >= 2 && owner.Runner.Birth != "" && owner.Runner.Executable != "" && owner.Runner.Command != ""
}

func (store darwinOwnershipStore) active() (darwinRunOwner, error) {
	var owner darwinRunOwner
	err := readDarwinAdminJSON(filepath.Join(store.root, darwinOwnerFile), store.uid, &owner)
	if err == nil && !owner.valid() {
		err = errors.New("invalid global administrator run owner; preserve recovery files")
	}
	return owner, err
}

func (store darwinOwnershipStore) claim(owner darwinRunOwner) error {
	if !owner.valid() {
		return errors.New("invalid native run identity")
	}
	if _, err := store.active(); !errors.Is(err, os.ErrNotExist) {
		return errors.New("previous native owner must be recovered first")
	}
	if err := securefile.Write(filepath.Join(store.root, darwinOwnerFile), owner); err != nil {
		return err
	}
	return syncDarwinDirectory(store.root)
}

func (store darwinOwnershipStore) proof(run string) (darwinRecoveryProof, error) {
	var proof darwinRecoveryProof
	dir := filepath.Join(store.root, filepath.Base(run))
	if err := checkDarwinAdminObject(dir, store.uid, true); err != nil {
		return proof, err
	}
	err := readDarwinAdminJSON(filepath.Join(dir, darwinRecoveryFile), store.uid, &proof)
	if err == nil && (proof.Version != 1 || proof.Owner.Run != run || !proof.Owner.valid() || proof.RestoredAt.IsZero()) {
		err = errors.New("invalid administrator restoration proof")
	}
	return proof, err
}

// seal records the observed restoration before releasing the global ownership
// fence. An interrupted seal can be retried by the same run.
func (store darwinOwnershipStore) seal(owner darwinRunOwner) error {
	current, err := store.active()
	if err != nil || current != owner {
		return errors.New("global administrator run changed during recovery")
	}
	if err = store.writeProof(owner); err != nil {
		return err
	}
	// Keep the receipt when removing the owner. If the deletion does not survive
	// a host crash, the old owner still fences the next profile until a retry.
	if err = os.Remove(filepath.Join(store.root, darwinOwnerFile)); err != nil {
		return err
	}
	return syncDarwinDirectory(store.root)
}

func (store darwinOwnershipStore) writeProof(owner darwinRunOwner) error {
	dir := filepath.Join(store.root, filepath.Base(owner.Run))
	if err := checkDarwinAdminObject(dir, store.uid, true); err != nil {
		return err
	}
	proof := darwinRecoveryProof{Version: 1, Owner: owner, RestoredAt: time.Now().UTC()}
	if err := securefile.Write(filepath.Join(dir, darwinRecoveryFile), proof); err != nil {
		return err
	}
	return syncDarwinDirectory(dir)
}

func darwinOwnerFor(run string, state State) (darwinRunOwner, error) {
	if err := ValidateRun(run); err != nil {
		return darwinRunOwner{}, err
	}
	info, err := os.Lstat(run)
	if err != nil {
		return darwinRunOwner{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || state.Manifest.Owner < 1 || int(stat.Uid) != state.Manifest.Owner {
		return darwinRunOwner{}, errors.New("run directory does not match the administrator journal")
	}
	spec := state.RunSpecDigest
	if spec == "" && state.Version == 1 {
		spec = runSpecDigest(immutableRunSpec(state.Manifest))
	}
	owner := darwinRunOwner{Version: 1, Run: run, UID: stat.Uid, Device: stat.Dev, Inode: stat.Ino, Spec: spec, Runner: state.Runner}
	if !owner.valid() {
		return darwinRunOwner{}, errors.New("administrator run identity is incomplete")
	}
	return owner, nil
}

// Called within state.lock. The owner cannot be released while this journal
// still owns native resources, and the owner record is replaced atomically.
func requireActiveDarwinOwner(run string, state State) error {
	store, err := openDarwinOwnershipStore(run)
	if err != nil {
		return err
	}
	owner, err := darwinOwnerFor(run, state)
	if err != nil {
		return err
	}
	active, err := store.active()
	if err != nil {
		return err
	}
	if active != owner {
		return errors.New("administrator run no longer owns native resources")
	}
	return nil
}

// Older frozen binaries published no global owner. Their administrator journal
// still fences new startups while it might own resources.
func (store darwinOwnershipStore) requireLegacyIdle() error {
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "netlaunch-") {
			continue
		}
		dir := filepath.Join(store.root, entry.Name())
		if err = checkDarwinAdminObject(dir, store.uid, true); err != nil {
			return err
		}
		path := filepath.Join(dir, "state.json")
		err = checkDarwinAdminObject(path, store.uid, false)
		if errors.Is(err, os.ErrNotExist) {
			continue // no native resources are created before the first state
		}
		if err != nil {
			return err
		}
		raw, err := securefile.Read(path, 4<<20, true)
		if err != nil {
			return err
		}
		var state struct {
			Version int    `json:"version"`
			Phase   string `json:"phase"`
		}
		if json.Unmarshal(raw, &state) != nil || (state.Version != 1 && state.Version != currentStateVersion) || state.Phase != "stopped" {
			return errors.New("previous native journal needs recovery first")
		}
	}
	return nil
}

// Called while holding active.lock. The root owner is durable before the caller
// freezes credentials, spawns children, touches DNS, or changes native routes.
func initializeDarwinOwner(run string) (State, error) {
	store, err := openDarwinOwnershipStore(run)
	if err != nil {
		return State{}, err
	}
	unlock, err := store.lock()
	if err != nil {
		return State{}, err
	}
	defer unlock()
	if _, err = store.active(); !errors.Is(err, os.ErrNotExist) {
		return State{}, errors.New("previous native owner must be recovered first")
	}
	if err = store.requireLegacyIdle(); err != nil {
		return State{}, err
	}
	if _, err = os.Lstat(filepath.Join(run, "STOP")); !errors.Is(err, os.ErrNotExist) {
		return State{}, errors.New("run was cancelled or its stop request cannot be checked")
	}
	state, err := initialize(run)
	if err != nil {
		return state, err
	}
	owner, err := darwinOwnerFor(run, state)
	if err != nil {
		return state, err
	}
	if err = store.claim(owner); err != nil {
		return state, err
	}
	return state, nil
}

func rejectDarwinUnjournaledOwner(run string) error {
	store, err := openDarwinOwnershipStore(run)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	unlock, err := store.lock()
	if err != nil {
		return err
	}
	defer unlock()
	active, err := store.active()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if filepath.Base(active.Run) == filepath.Base(run) {
		return errors.New("administrator run is missing its recovery journal")
	}
	return nil
}

// Called under recovery.lock after reading protected state. A legacy mutable
// run path is accepted only if it matches the original protected command line.
func bindDarwinRecovery(run string, state State) (darwinRunOwner, bool, error) {
	store, err := openDarwinOwnershipStore(run)
	if err != nil {
		return darwinRunOwner{}, false, err
	}
	unlock, err := store.lock()
	if err != nil {
		return darwinRunOwner{}, false, err
	}
	defer unlock()
	active, err := store.active()
	if err == nil && active.Run != run && state.Phase == "stopped" && filepath.Base(active.Run) != filepath.Base(run) {
		return darwinRunOwner{}, false, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return darwinRunOwner{}, false, err
	}
	if errors.Is(err, os.ErrNotExist) && state.Phase == "stopped" {
		return darwinRunOwner{}, false, nil
	}
	owner, ownerErr := darwinOwnerFor(run, state)
	if ownerErr != nil {
		return owner, false, ownerErr
	}
	if err == nil {
		if active != owner {
			return owner, false, errors.New("only the recorded native run can release global ownership")
		}
		return owner, true, nil
	}
	if state.Runner.Command != strings.Join([]string{state.Runner.Executable, "_serve", "--run", run}, " ") {
		return owner, false, errors.New("legacy coordinator did not publish the requested run identity")
	}
	if err = store.claim(owner); err != nil {
		return owner, false, err
	}
	return owner, true, nil
}

func sealDarwinRecovery(run string, owner darwinRunOwner) error {
	store, err := openDarwinOwnershipStore(run)
	if err != nil {
		return err
	}
	unlock, err := store.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return store.seal(owner)
}

func verifyDarwinRecovery(run string) error {
	store, err := openDarwinOwnershipStore(run)
	if err != nil {
		return err
	}
	unlock, err := store.lock()
	if err != nil {
		return err
	}
	defer unlock()
	state, err := load(run)
	if err != nil || state.Phase != "stopped" {
		return errors.New("administrator run does not have a stopped journal")
	}
	owner, err := darwinOwnerFor(run, state)
	if err != nil {
		return err
	}
	active, activeErr := store.active()
	if activeErr == nil && filepath.Base(active.Run) == filepath.Base(run) {
		return errors.New("administrator run is still fenced for recovery")
	}
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return activeErr
	}
	proof, err := store.proof(run)
	if err == nil && proof.Owner == owner {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) || !errors.Is(activeErr, os.ErrNotExist) {
		return errors.New("administrator restoration proof is unavailable for this run")
	}
	return store.attestLegacyStop(state, owner, verifyDarwinRestoredResources)
}

// A completed legacy run did not write a receipt. Prove restoration from its
// protected journal and fresh native observations while excluding startups.
func (store darwinOwnershipStore) attestLegacyStop(state State, owner darwinRunOwner, verify func(State) error) error {
	command := strings.Join([]string{owner.Runner.Executable, "_serve", "--run", owner.Run}, " ")
	if state.Phase != "stopped" || owner.Runner.Command != command {
		return errors.New("legacy restoration does not identify the original run")
	}
	// The caller holds ownership.lock. Try once so a coordinator that holds
	// active.lock while waiting for ownership.lock cannot deadlock with us.
	unlock, err := securefile.Lock(filepath.Join(store.root, "active.lock"), 0)
	if err != nil {
		return errors.New("a native coordinator is still active")
	}
	defer unlock()
	if _, err := store.active(); !errors.Is(err, os.ErrNotExist) {
		return errors.New("another native run still owns networking")
	}
	if err := store.requireLegacyIdle(); err != nil {
		return err
	}
	if err := verify(state); err != nil {
		return err
	}
	return store.writeProof(owner)
}

func darwinProcessGone(pid int, birth string) error {
	if pid < 2 || birth == "" {
		return errors.New("recovery process identity is incomplete")
	}
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.pid", pid)
	if err != nil || len(processes) > 1 {
		return errors.New("unable to verify native process absence")
	}
	if len(processes) == 0 {
		return nil
	}
	if int(processes[0].Proc.P_pid) != pid {
		return errors.New("unable to verify native process identity")
	}
	const zombie = 5 // SZOMB in Darwin's sys/proc.h
	if processes[0].Proc.P_stat == zombie {
		return nil // exited and awaiting parent collection, with no resources
	}
	current, err := platform.Process(pid)
	if err != nil || current.PID != pid || current.Birth == "" || current.Birth == birth {
		return errors.New("owned process remains or cannot be verified")
	}
	return nil // known reused PID; never signal the replacement
}

func verifyDarwinRestoredResources(s State) error {
	// Self recovery happens after the coordinator has stopped its work, while
	// it still holds active.lock. Its deferred exit cannot overlap a new start.
	if s.Runner.PID != os.Getpid() {
		if err := darwinProcessGone(s.Runner.PID, s.Runner.Birth); err != nil {
			return err
		}
	}
	for _, child := range s.Children {
		if err := darwinProcessGone(child.PID, child.Birth); err != nil {
			return err
		}
	}
	if err := verifyDarwinRecoveredInterfaces(s); err != nil {
		return err
	}
	if len(s.Routes) > 0 {
		if err := verifyDarwinRestoredRoutes(s.Routes); err != nil {
			return err
		}
	}
	for service, change := range s.DNS {
		value, err := platform.DNS(service)
		if err != nil {
			return err
		}
		if needed, err := restoreDNS(value, change); needed || err != nil {
			return errors.New("original DNS restoration not verified")
		}
	}
	return nil
}

func verifyDarwinRestoredRoutes(recorded []OwnedRoute) error {
	routes, err := platform.Routes()
	if err != nil {
		return err
	}
	for _, route := range recorded {
		if route.State != "removed" {
			return errors.New("native route restoration is incomplete")
		}
		for _, actual := range routes {
			if keyMatch(route.Route, actual) {
				return errors.New("owned route is still present or cannot be verified")
			}
		}
	}
	return nil
}

func verifyDarwinRecoveredInterfaces(s State) error {
	if len(s.Children) == 0 {
		return nil // startup did not release a native resource creator
	}
	interfaces, err := platform.Interfaces()
	if err != nil {
		return err
	}
	if hasDarwinCandidateInterface(s, interfaces) {
		return errors.New("candidate interface remains; recovery stopped")
	}
	return nil
}
