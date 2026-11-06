package winservice

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"
)

type mockPending struct {
	trace     *[]string
	waitError error
	ready     bool
}

func (m mockPending) Wait() (bool, error) {
	*m.trace = append(*m.trace, "wait")
	return m.ready, m.waitError
}
func (m mockPending) Complete() error { *m.trace = append(*m.trace, "complete"); return nil }
func (m mockPending) CancelAndDrain() error {
	*m.trace = append(*m.trace, "cancel", "drain")
	return nil
}
func TestPendingErrorCancelsAndDrainsBeforeEventRelease(t *testing.T) {
	trace := []string{}
	func() {
		defer func() { trace = append(trace, "event-close") }()
		err := finishPending(context.Background(), func() bool { return false }, mockPending{trace: &trace, waitError: errors.New("wait failed")})
		if err == nil {
			t.Fatal("wait error hidden")
		}
	}()
	if !reflect.DeepEqual(trace, []string{"wait", "cancel", "drain", "event-close"}) {
		t.Fatalf("native memory released before drain: %v", trace)
	}
}
func TestPendingCancellationAndDeadlineAlwaysDrain(t *testing.T) {
	for _, expired := range []bool{false, true} {
		trace := []string{}
		ctx, cancel := context.WithCancel(context.Background())
		if !expired {
			cancel()
		}
		err := finishPending(ctx, func() bool { return expired }, mockPending{trace: &trace})
		cancel()
		if err == nil || !reflect.DeepEqual(trace, []string{"cancel", "drain"}) {
			t.Fatalf("pending cancellation did not drain: %v %v", trace, err)
		}
	}
}

type partialFrame struct {
	set     bool
	partial bool
	timeout bool
}

func (p *partialFrame) SetDeadline(at time.Time) error {
	if time.Until(at) > 6*time.Second {
		return errors.New("unbounded deadline")
	}
	p.set = true
	return nil
}
func (p *partialFrame) Read(buffer []byte) (int, error) {
	if !p.set {
		panic("partial frame did not get a deadline")
	}
	if !p.partial {
		p.partial = true
		return copy(buffer, `{"version":1`), nil
	}
	p.timeout = true
	return 0, context.DeadlineExceeded
}
func TestPartialFramesDoNotOwnAllServiceSlotsIndefinitely(t *testing.T) {
	b, _, _ := newTestBroker(t, &fakeBackend{}, testBinding("profile"))
	var wg sync.WaitGroup
	streams := make([]*partialFrame, 8)
	for i := range streams {
		streams[i] = &partialFrame{}
		wg.Add(1)
		go func(stream *partialFrame) {
			defer wg.Done()
			_ = b.ServeConnection(context.Background(), stream, io.Discard, func() (VerifiedPrincipal, error) {
				t.Error("partial frame authenticated or executed")
				return VerifiedPrincipal{}, nil
			})
		}(streams[i])
	}
	wg.Wait()
	for _, stream := range streams {
		if !stream.timeout {
			t.Fatal("partial frame retained its slot")
		}
	}
}
