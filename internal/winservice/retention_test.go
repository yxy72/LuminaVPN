package winservice

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	p "netlaunch/internal/serviceprotocol"
)

func TestCompletedHistoryCannotExhaustPriorityRestoration(t *testing.T) {
	var calls atomic.Int32
	b, _, _ := newTestBroker(t, &fakeBackend{execute: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
		if calls.Add(1) == 1 {
			return Completion{}, safeError("STOP_REQUIRED")
		}
		return Completion{}, nil
	}}, testBinding("profile"))
	var first p.Operation
	for i := 0; i < 1024; i++ {
		mutation := p.Mutation{RequestID: fmt.Sprintf("request-%d", i), ProfileID: "profile", ExpectedRevision: 1, Kind: p.NodeSelect, Selection: &p.SelectionPayload{NodeID: "auto"}}
		op, err := b.Submit(context.Background(), testPeer(), mutation)
		if err != nil {
			t.Fatal(err)
		}
		waitOperation(t, b, op.ID)
		if i == 0 {
			first = op
		}
	}
	stop, err := b.Submit(context.Background(), testPeer(), stopMutation("exit", "profile", ""))
	if err != nil {
		t.Fatal("completed history blocked priority exit", err)
	}
	if final := waitOperation(t, b, stop.ID); !final.Restored || final.Error != nil {
		t.Fatal("priority restoration did not complete")
	}
	b.mu.Lock()
	size := len(b.operations)
	b.mu.Unlock()
	if size > 1024 {
		t.Fatal("completed cache did not remain bounded")
	}
	history, err := b.Operation(context.Background(), testPeer(), first.ID)
	if err != nil || history.FirstFailure == nil || history.FirstFailure.Code != "STOP_REQUIRED" {
		t.Fatal("eviction lost original durable failure")
	}
	if _, err = b.Submit(context.Background(), testPeer(), p.Mutation{RequestID: "request-0", ProfileID: "profile", ExpectedRevision: 1, Kind: p.NodeSelect, Selection: &p.SelectionPayload{NodeID: "auto"}}); err == nil {
		t.Fatal("evicted request executed a second time")
	}
	if calls.Load() != 1024 {
		t.Fatal("history replay entered backend")
	}
}
func TestConcurrentStopAndQuitKeepEachRequestIdentityWithOneRecovery(t *testing.T) {
	for _, firstKind := range []p.Kind{p.TakeoverStop, p.ExitRestore} {
		t.Run(string(firstKind), func(t *testing.T) {
			entered, finish := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			binding := testBinding("profile")
			binding.RunRef = "run-A"
			b, _, _ := newTestBroker(t, &fakeBackend{stop: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
				calls.Add(1)
				close(entered)
				<-finish
				return Completion{Restored: true}, nil
			}}, binding)
			firstMutation := stopMutation("first", "profile", binding.RunRef)
			firstMutation.Kind = firstKind
			first, err := b.Submit(context.Background(), testPeer(), firstMutation)
			if err != nil {
				t.Fatal(err)
			}
			<-entered
			second, err := b.Submit(context.Background(), testPeer(), stopMutation("quit", "profile", binding.RunRef))
			if err != nil {
				t.Fatal(err)
			}
			if second.ID == first.ID || second.RequestID != "quit" || second.Kind != p.ExitRestore || second.AliasOf != first.ID {
				t.Fatal("quit inherited another request envelope")
			}
			close(finish)
			firstDone, secondDone := waitOperation(t, b, first.ID), waitOperation(t, b, second.ID)
			if !firstDone.Restored || !secondDone.Restored || firstDone.Error != nil || secondDone.Error != nil || calls.Load() != 1 || secondDone.RequestID != "quit" || secondDone.Kind != p.ExitRestore {
				t.Fatal("shared restore did not preserve strict per-request acknowledgements")
			}
		})
	}
}
