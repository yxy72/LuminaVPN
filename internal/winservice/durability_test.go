package winservice

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	p "netlaunch/internal/serviceprotocol"
)

type failingOwners struct {
	*MemoryStore
	calls  atomic.Int32
	failAt int32
}

type shutdownSealingBackend struct {
	*fakeBackend
	sealed atomic.Bool
}

func (f *shutdownSealingBackend) SealForShutdown() { f.sealed.Store(true) }

func (s *failingOwners) Save(b Binding) error {
	if s.calls.Add(1) == s.failAt {
		return errors.New("simulated ownership persistence failure")
	}
	return s.MemoryStore.Save(b)
}

type failingLedger struct {
	MemoryLedger
	calls  atomic.Int32
	failAt int32
}

func (l *failingLedger) Save(op p.Operation) error {
	if l.calls.Add(1) == l.failAt {
		return errors.New("simulated journal persistence failure")
	}
	return l.MemoryLedger.Save(op)
}

func durableTestBroker(t *testing.T, backend Backend, owner OwnershipStore, ledger Ledger) *Broker {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	b, err := NewBroker(ctx, backend, owner, ledger, "S-1-5-18", "service-1")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPersistenceFailureBeforeAcceptanceNeverStartsBackend(t *testing.T) {
	for _, failJournal := range []bool{false, true} {
		t.Run(map[bool]string{false: "owner", true: "journal"}[failJournal], func(t *testing.T) {
			var executions atomic.Int32
			owners := &failingOwners{MemoryStore: &MemoryStore{Bindings: map[string]Binding{"profile": testBinding("profile")}}}
			ledger := &failingLedger{}
			if failJournal {
				ledger.failAt = 1
			} else {
				owners.failAt = 1
			}
			b := durableTestBroker(t, &fakeBackend{execute: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
				executions.Add(1)
				return Completion{}, nil
			}}, owners, ledger)
			if _, err := b.Submit(context.Background(), testPeer(), startMutation("start", "profile")); err == nil {
				t.Fatal("undurable acceptance acknowledged")
			}
			if executions.Load() != 0 {
				t.Fatal("backend executed without durable ownership/journal")
			}
		})
	}
}

func TestFailedFinalJournalRetainsRecoveryBindingAndCannotAcknowledgeExit(t *testing.T) {
	binding := testBinding("profile")
	binding.RunRef, binding.PreparedRunID, binding.SpecDigest = "run-A", "netlaunch-"+strings.Repeat("a", 32), strings.Repeat("b", 64)
	owners := &MemoryStore{Bindings: map[string]Binding{"profile": binding}}
	b := durableTestBroker(t, &fakeBackend{}, owners, &failingLedger{failAt: 2})
	op, err := b.Submit(context.Background(), testPeer(), stopMutation("stop", "profile", binding.RunRef))
	if err != nil {
		t.Fatal(err)
	}
	final := waitOperation(t, b, op.ID)
	if final.Completed || final.Error == nil || final.FirstFailure == nil || final.FirstFailure.Code != "JOURNAL_UNAVAILABLE" {
		t.Fatalf("failed persistence became clean exit: %#v", final)
	}
	saved, _ := owners.Lookup("profile")
	if saved.RunRef != binding.RunRef || saved.PreparedRunID != binding.PreparedRunID {
		t.Fatal("journal failure lost durable recovery reference")
	}
}

func TestFailedOwnershipClearCannotAcknowledgeExit(t *testing.T) {
	binding := testBinding("profile")
	binding.RunRef = "run-A"
	owners := &failingOwners{MemoryStore: &MemoryStore{Bindings: map[string]Binding{"profile": binding}}, failAt: 3}
	b := durableTestBroker(t, &fakeBackend{}, owners, &MemoryLedger{})
	op, err := b.Submit(context.Background(), testPeer(), stopMutation("stop", "profile", binding.RunRef))
	if err != nil {
		t.Fatal(err)
	}
	final := waitOperation(t, b, op.ID)
	if final.Completed || final.Error == nil || final.Error.Code != "OWNERSHIP_UNAVAILABLE" {
		t.Fatalf("ownership clear became clean ACK: %#v", final)
	}
	saved, _ := owners.Lookup("profile")
	if saved.RunRef != binding.RunRef {
		t.Fatal("failed clear removed recovery reference")
	}
}

func TestPreparedRunBindingIsImmutableAndDurableBeforeServe(t *testing.T) {
	var broker *Broker
	checked := make(chan error, 1)
	broker, owners, _ := newTestBroker(t, &fakeBackend{execute: func(_ context.Context, a AuthorizedOperation, _ func(Progress)) (Completion, error) {
		prepared := PreparedRun{EngineRunID: "netlaunch-" + strings.Repeat("a", 32), ExecutorSID: "S-1-5-18", SpecDigest: strings.Repeat("b", 64), Mode: a.Binding().Mode, Deadline: a.Binding().Deadline}
		wrong := prepared
		wrong.Deadline = prepared.Deadline.Add(time.Second)
		if broker.BindPreparedRun(a, wrong) == nil {
			checked <- errors.New("deadline renewal accepted")
			return Completion{}, nil
		}
		if err := broker.BindPreparedRun(a, prepared); err != nil {
			checked <- err
			return Completion{}, nil
		}
		saved, _ := broker.owners.Lookup("profile")
		if saved.PreparedRunID != prepared.EngineRunID || saved.SpecDigest != prepared.SpecDigest {
			checked <- errors.New("identity was not durably published")
			return Completion{}, nil
		}
		wrong = prepared
		wrong.EngineRunID = "netlaunch-" + strings.Repeat("c", 32)
		if broker.BindPreparedRun(a, wrong) == nil {
			checked <- errors.New("prepared identity replaced")
			return Completion{}, nil
		}
		checked <- nil
		return Completion{}, nil
	}}, testBinding("profile"))
	mutation := startMutation("start", "profile")
	mutation.Start.Mode = "validation"
	mutation.Start.ValidationSeconds = 120
	op, err := broker.Submit(context.Background(), testPeer(), mutation)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-checked; err != nil {
		t.Fatal(err)
	}
	if final := waitOperation(t, broker, op.ID); final.Error != nil {
		t.Fatal(final.Error)
	}
	saved, _ := owners.Lookup("profile")
	if saved.PreparedRunID == "" {
		t.Fatal("prepared binding disappeared")
	}
}

func TestStopWaitsForLatePrepareAndUsesDurableRecoveryIdentity(t *testing.T) {
	var broker *Broker
	entered := make(chan struct{})
	bindResult := make(chan error, 1)
	recovered := make(chan Binding, 1)
	broker, owners, _ := newTestBroker(t, &fakeBackend{execute: func(ctx context.Context, a AuthorizedOperation, _ func(Progress)) (Completion, error) {
		close(entered)
		<-ctx.Done()
		bindResult <- broker.BindPreparedRun(a, PreparedRun{EngineRunID: "netlaunch-" + strings.Repeat("a", 32), ExecutorSID: "S-1-5-18", SpecDigest: strings.Repeat("b", 64), Mode: a.Binding().Mode, Deadline: a.Binding().Deadline})
		return Completion{}, ctx.Err()
	}, stop: func(_ context.Context, a AuthorizedOperation, _ func(Progress)) (Completion, error) {
		recovered <- a.Binding()
		return Completion{Restored: true}, nil
	}}, testBinding("profile"))
	start, err := broker.Submit(context.Background(), testPeer(), startMutation("start", "profile"))
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	stop, err := broker.Submit(context.Background(), testPeer(), stopMutation("exit", "profile", start.RunRef))
	if err != nil {
		t.Fatal(err)
	}
	if err = <-bindResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("late prepare authorized serve: %v", err)
	}
	seen := <-recovered
	if seen.PreparedRunID == "" || seen.SpecDigest == "" {
		t.Fatal("priority recovery used pre-prepare snapshot")
	}
	if final := waitOperation(t, broker, stop.ID); !final.Completed || !final.Restored || final.Error != nil {
		t.Fatalf("restore failed: %#v", final)
	}
	saved, _ := owners.Lookup("profile")
	if saved.RunRef != "" || saved.PreparedRunID != "" || saved.SpecDigest != "" || saved.Mode != "" || !saved.Deadline.IsZero() {
		t.Fatalf("restored run was retained as next run identity: %#v", saved)
	}
}

func TestShutdownRestoresUsingServiceOwnershipWithoutCaller(t *testing.T) {
	binding := testBinding("profile")
	binding.RunRef = "run-A"
	binding.PreparedRunID = "netlaunch-" + strings.Repeat("a", 32)
	var verified atomic.Bool
	b, owners, _ := newTestBroker(t, &fakeBackend{stop: func(_ context.Context, a AuthorizedOperation, _ func(Progress)) (Completion, error) {
		verified.Store(a.ServiceStop() && !a.Principal().Verified() && a.Binding().PreparedRunID == binding.PreparedRunID)
		return Completion{Restored: true}, nil
	}}, binding)
	if err := b.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !verified.Load() {
		t.Fatal("SCM restoration depended on GUI identity or lost owned run")
	}
	saved, _ := owners.Lookup("profile")
	if saved.RunRef != "" {
		t.Fatal("restoration was not persisted")
	}
}

func TestFailedStopAllowsNewRequestWhilePreservingOriginalFailure(t *testing.T) {
	binding := testBinding("profile")
	binding.RunRef = "run-A"
	var calls atomic.Int32
	b, _, _ := newTestBroker(t, &fakeBackend{stop: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
		if calls.Add(1) == 1 {
			return Completion{}, errors.New("transient failure")
		}
		return Completion{Restored: true}, nil
	}}, binding)
	first, err := b.Submit(context.Background(), testPeer(), stopMutation("stop1", "profile", binding.RunRef))
	if err != nil {
		t.Fatal(err)
	}
	failed := waitOperation(t, b, first.ID)
	if failed.Error == nil || failed.FirstFailure == nil {
		t.Fatal("initial failure missing")
	}
	second, err := b.Submit(context.Background(), testPeer(), stopMutation("stop2", "profile", binding.RunRef))
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID {
		t.Fatal("failed stop permanently prevented recovery retry")
	}
	recovered := waitOperation(t, b, second.ID)
	if !recovered.Restored || recovered.Error != nil || calls.Load() != 2 {
		t.Fatalf("retry did not restore: %#v", recovered)
	}
	history, err := b.Operation(context.Background(), testPeer(), first.ID)
	if err != nil || history.FirstFailure == nil || history.Error == nil || history.Restored {
		t.Fatal("later success erased original failed attempt")
	}
}

func TestInFlightStopJournalFailureDoesNotStartParallelRecovery(t *testing.T) {
	binding := testBinding("profile")
	binding.RunRef = "run-A"
	entered, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	owners := &MemoryStore{Bindings: map[string]Binding{"profile": binding}}
	b := durableTestBroker(t, &fakeBackend{stop: func(_ context.Context, _ AuthorizedOperation, progress func(Progress)) (Completion, error) {
		calls.Add(1)
		progress(Progress{Phase: "restoring"})
		close(entered)
		<-finish
		return Completion{Restored: true}, nil
	}}, owners, &failingLedger{failAt: 2})
	first, err := b.Submit(context.Background(), testPeer(), stopMutation("stop1", "profile", binding.RunRef))
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	second, err := b.Submit(context.Background(), testPeer(), stopMutation("stop2", "profile", binding.RunRef))
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID || second.AliasOf != first.ID || second.RequestID != "stop2" || calls.Load() != 1 {
		t.Fatal("failed progress persistence spawned simultaneous restore")
	}
	close(finish)
	waitOperation(t, b, first.ID)
}

func TestSCMShutdownWaitsForAlreadyRunningStopAndRejectsLateSubmissions(t *testing.T) {
	binding := testBinding("profile")
	binding.RunRef = "run-A"
	entered, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	b, _, _ := newTestBroker(t, &fakeBackend{stop: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
		if calls.Add(1) != 1 {
			t.Error("parallel SCM recovery")
		}
		close(entered)
		<-finish
		return Completion{Restored: true}, nil
	}}, binding)
	sealing := &shutdownSealingBackend{fakeBackend: b.backend.(*fakeBackend)}
	b.backend = sealing
	_, err := b.Submit(context.Background(), testPeer(), stopMutation("stop1", "profile", binding.RunRef))
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	done := make(chan error, 1)
	go func() { done <- b.Shutdown(context.Background()) }()
	until := time.Now().Add(time.Second)
	for {
		b.mu.Lock()
		stopping := b.shuttingDown
		b.mu.Unlock()
		if stopping {
			break
		}
		if time.Now().After(until) {
			t.Fatal("SCM stop did not enter barrier")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err = b.Submit(context.Background(), testPeer(), stopMutation("late", "profile", binding.RunRef)); err == nil {
		t.Fatal("late client work entered SCM shutdown")
	}
	if !sealing.sealed.Load() {
		t.Fatal("SCM did not permanently seal backend before joining ordinary stop")
	}
	select {
	case <-done:
		t.Fatal("SCM restore ACK before in-flight stop completed")
	default:
	}
	close(finish)
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SCM stop did not settle")
	}
	if calls.Load() != 1 {
		t.Fatal("SCM performed parallel duplicate recovery")
	}
	if !sealing.sealed.Load() {
		t.Fatal("coalesced stop bypassed permanent backend seal")
	}
}
