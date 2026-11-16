//go:build darwin || windows

package engine

import (
	"context"
	"errors"
	"netlaunch/internal/personalroute"
	"netlaunch/internal/policy"
	"netlaunch/internal/selector"
	"time"
)

func wait(ctx context.Context, run string, limit time.Duration, check func(context.Context) error) error {
	return waitReady(ctx, limit, func() error { return pulse(run) }, check)
}

func choose(ctx context.Context, run string, p *selector.Policy, verification *personalVerification) error {
	if verification.pending() {
		return applyPersonalSamples(ctx, run, p, verification, time.Now(), nil)
	}
	probes, err := personalProbeURLs(run)
	if err != nil {
		return err
	}
	started := time.Now()
	values := measurePersonal(ctx, run, p.NextBatch(8), probes)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return applyPersonalSamples(ctx, run, p, verification, started, values)
}

func personalProbeURLs(run string) ([]string, error) {
	s, err := load(run)
	if err != nil {
		return nil, err
	}
	var probes []string
	for _, probe := range s.Manifest.Config.Probes {
		if probe.Channel == "personal" {
			probes = append(probes, probe.URL)
		}
	}
	return probes, nil
}

func measurePersonal(ctx context.Context, run string, names, probes []string) map[string]int {
	return measurePersonalWith(ctx, names, probes, func(ctx context.Context, path string, out any) error {
		return apiContext(ctx, run, "GET", path, nil, out)
	})
}

func measurePersonalWith(ctx context.Context, names, probes []string, request func(context.Context, string, any) error) map[string]int {
	return sampleNodes(ctx, names, 6*time.Second, 8, func(ctx context.Context, name string) (int, bool) {
		sample := independentNode(ctx, name, "", "", personalroute.Generation{}, probes, request)
		switch sample.Observation.Outcome {
		case personalroute.Healthy:
			return sample.Latency, true
		case personalroute.PathFailed:
			return -1, true
		default:
			return 0, false
		}
	})
}

func applyPersonalSamples(parent context.Context, run string, p *selector.Policy, verification *personalVerification, started time.Time, values map[string]int) error {
	return applyPersonalSamplesWith(parent, run, p, verification, func(now time.Time) (string, string) { return p.DecideSamplesSince(now, started, values) })
}

func applyPersonalTimedSamples(parent context.Context, run string, p *selector.Policy, verification *personalVerification, samples map[string]selector.TimedSample) error {
	return applyPersonalSamplesWith(parent, run, p, verification, func(now time.Time) (string, string) { return p.DecideTimedSamples(now, samples) })
}

func applyPersonalSamplesWith(parent context.Context, run string, p *selector.Policy, verification *personalVerification, decide func(time.Time) (string, string)) error {
	s, err := load(run)
	if err != nil {
		return err
	}
	return verification.advance(parent, run, s, p, decide)
}

func rejectPersonal(run string, p *selector.Policy, node string, failure error, scope string) error {
	if e := selectPersonal(run, selector.Reject); e != nil {
		return e
	}
	return recordPersonalRejection(p, node, failure, scope, func(fn func(*State) error) error { return update(run, fn) })
}

func recordPersonalRejection(p *selector.Policy, node string, failure error, scope string, updateState func(func(*State) error) error) error {
	checked := time.Now()
	if nodeProbeFailure(failure) {
		p.ReportFailure(node, checked)
	} else if probeReason(failure) == "http_status_rejected" {
		p.ReportServiceRejection(node, checked)
	}
	p.Commit(selector.Reject, checked)
	return updateState(func(s *State) error {
		s.Personal = selector.Reject
		s.Error = failure.Error()
		personalUnavailable(s, probeReason(failure))
		h := s.Channels["personal"]
		h.ChannelStatus = observeChannel(ChannelStatus{}, failure, checked, policy.Probe{Channel: "personal"})
		h.ProbeScope = scope
		s.Channels["personal"] = h
		if s.Phase == "ready" {
			s.Phase = "degraded"
		}
		return nil
	})
}

func ensurePersonalSelection(ctx context.Context, run string, p *selector.Policy, verification *personalVerification) error {
	if p.Current != selector.Reject {
		return nil
	}
	if e := choose(ctx, run, p, verification); e != nil {
		return e
	}
	if p.Current == selector.Reject {
		return errors.New("personal proxy is not ready")
	}
	return nil
}
