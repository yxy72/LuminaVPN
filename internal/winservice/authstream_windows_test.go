//go:build windows

package winservice

import (
	"context"
	"errors"
	"testing"
)

func TestPrivateAuthReadDetachDoesNotCloseTheOwnedConversation(t *testing.T) {
	conversation := &UserAuthentication{events: make(chan authRead, 1), closing: make(chan struct{}), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := conversation.ReadEvent(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("reader did not detach")
	}
	select {
	case <-conversation.closing:
		t.Fatal("RPC read cancellation closed owned worker")
	default:
	}
	conversation.events <- authRead{event: UserAuthEvent{Kind: "challenge", ChallengeID: "reattachable"}}
	if event, err := conversation.ReadEvent(context.Background()); err != nil || event.ChallengeID != "reattachable" {
		t.Fatal("later reader could not attach")
	}
}
