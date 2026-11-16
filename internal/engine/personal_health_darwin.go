//go:build darwin

package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"time"

	"netlaunch/internal/personalroute"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/selector"
)

type darwinHealthBinding struct {
	spec    string
	network platform.Network
	wake    string
	intent  uint64
}

func darwinHealthScope(s State, wake string) darwinHealthBinding {
	return darwinHealthBinding{s.RunSpecDigest, s.Manifest.Network, wake, s.ChannelGeneration}
}

type darwinPersonalHealth struct {
	binding   darwinHealthBinding
	gen       personalroute.Generation
	sequence  uint64
	pending   <-chan independentSweep
	cancel    context.CancelFunc
	latest    independentSweep
	sampledAt map[string]time.Time
}

func (h *darwinPersonalHealth) reset() {
	if h.cancel != nil {
		h.cancel()
		h.cancel = nil
	}
	h.gen = personalroute.Generation{}
	h.latest = independentSweep{}
	h.sampledAt = nil
	// Wait for canceled workers to drain before starting another pool.
}

func (h *darwinPersonalHealth) observe() {
	for h.pending != nil {
		select {
		case next, open := <-h.pending:
			if !open {
				h.pending = nil
				h.reset()
				return
			}
			if next.Generation == h.gen {
				h.latest = next
			}
		default:
			return
		}
	}
}

func (h *darwinPersonalHealth) advance(ctx context.Context, run string, s State, wake string, nodes []policy.Node) {
	scope := darwinHealthScope(s, wake)
	if h.binding != scope {
		h.reset()
		h.binding = scope
	}
	h.observe()
	if h.pending != nil || len(nodes) == 0 || !currentIntent(s).Personal || ctx.Err() != nil {
		return
	}
	h.sequence++
	network, _ := json.Marshal(scope.network)
	digest := sha256.Sum256(append(network, []byte(wake)...))
	h.gen = personalroute.Generation{
		Run: filepath.Base(run), Network: hex.EncodeToString(digest[:]), Probe: strconv.FormatUint(h.sequence, 10),
	}
	targets, evidenceScope := personalMeasurementTargets(s.Manifest.Config.Probes)
	scheduler := newIndependentScheduler(nodes, targets, h.gen, evidenceScope)
	work, cancel := context.WithCancel(ctx)
	h.cancel = cancel
	h.sampledAt = make(map[string]time.Time)
	h.pending = scheduler.start(work, func(c context.Context, path string, out any) error {
		return apiContext(c, run, "GET", path, nil, out)
	})
}

func (h *darwinPersonalHealth) directDeadline(s State, wake string, nodes []policy.Node, now time.Time) time.Time {
	h.observe()
	if !currentIntent(s).Personal || h.binding != darwinHealthScope(s, wake) || h.latest.Generation != h.gen {
		return time.Time{}
	}
	return fallbackDecisionWithCoverage(currentIntent(s), nodes, h.gen, h.latest.Samples, now, h.latest.CoverageReason).ExpiresAt
}

func (h *darwinPersonalHealth) ranking() map[string]selector.TimedSample {
	h.observe()
	if h.sampledAt == nil {
		return nil
	}
	var values map[string]selector.TimedSample
	for _, sample := range h.latest.Samples {
		observation := sample.Observation
		if !observation.FinishedAt.After(h.sampledAt[sample.Name]) {
			continue
		}
		var delay int
		switch observation.Outcome {
		case personalroute.Healthy:
			delay = sample.Latency
		case personalroute.PathFailed:
			delay = -1
		default:
			continue
		}
		if values == nil {
			values = make(map[string]selector.TimedSample)
		}
		h.sampledAt[sample.Name] = observation.FinishedAt
		values[sample.Name] = selector.TimedSample{Latency: delay, StartedAt: observation.StartedAt, FinishedAt: observation.FinishedAt}
	}
	return values
}
