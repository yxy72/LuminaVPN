//go:build windows

package winservice

import (
	"context"
	"testing"
	"time"
)

type authWriteFixture struct{ write func([]byte) (int, error) }

func (f authWriteFixture) Write(data []byte) (int, error) { return f.write(data) }
func (f authWriteFixture) Close() error                   { return nil }

func TestPrivateAuthNextChallengeMayArriveBeforeResponseWriteReturns(t *testing.T) {
	first := UserAuthEvent{Version: 1, Kind: "challenge", ChallengeID: "first", Sequence: 1, ChallengeKind: "username", Expires: time.Now().Add(time.Minute)}
	next := UserAuthEvent{Version: 1, Kind: "challenge", ChallengeID: "second", Sequence: 2, ChallengeKind: "otp", Expires: first.Expires}
	c := &UserAuthentication{current: first, sequence: 1, closing: make(chan struct{}), done: make(chan struct{})}
	writes := 0
	c.in = authWriteFixture{write: func(data []byte) (int, error) {
		writes++
		// This is the read goroutine publishing a new worker frame while the
		// writer is still inside Write. No worker, socket or process is run.
		if err := c.acceptEvent(next); err != nil {
			return 0, err
		}
		return len(data), nil
	}}
	response := UserAuthResponse{ChallengeID: first.ChallengeID, Sequence: 1, Username: "fixture-user"}
	if err := c.Respond(context.Background(), response); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	got := c.current
	c.mu.Unlock()
	if got.ChallengeID != next.ChallengeID || got.Sequence != 2 {
		t.Fatal("response completion erased the next native form")
	}
	if err := c.Respond(context.Background(), response); err == nil || writes != 1 {
		t.Fatal("consumed challenge was replayed")
	}
}

func TestPrivateAuthUnansweredOrRepeatedChallengeStillRejected(t *testing.T) {
	first := UserAuthEvent{Kind: "challenge", ChallengeID: "first", Sequence: 1}
	c := &UserAuthentication{current: first, sequence: 1}
	if c.acceptEvent(UserAuthEvent{Kind: "challenge", ChallengeID: "second", Sequence: 2}) == nil {
		t.Fatal("unsolicited next form bypassed an unanswered challenge")
	}
	c.current = UserAuthEvent{}
	if c.acceptEvent(first) == nil {
		t.Fatal("consumed sequence was reused")
	}
}
