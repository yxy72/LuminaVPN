package engine

import (
	"context"
	"sync"
	"time"

	"netlaunch/internal/policy"
)

type probeObservation struct {
	probe   policy.Probe
	err     error
	checked time.Time
}

// Workers perform read-only checks. The coordinator publishes the complete
// batch and changes gates afterwards; unfinished checks remain unknown.
func runProbeBatch(parent context.Context, probes []policy.Probe, budget time.Duration, parallel int, check func(context.Context, policy.Probe) error) []probeObservation {
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	observed := make([]probeObservation, len(probes))
	for i, p := range probes {
		observed[i] = probeObservation{p, context.DeadlineExceeded, time.Now()}
	}
	if parallel < 1 {
		parallel = 1
	}
	type result struct {
		index       int
		observation probeObservation
	}
	jobs, done := make(chan int), make(chan result, len(probes))
	var workers sync.WaitGroup
	for i := 0; i < parallel && i < len(probes); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					return
				}
				p := probes[index]
				err := check(ctx, p)
				if ctx.Err() != nil {
					err = ctx.Err()
				}
				done <- result{index, probeObservation{p, err, time.Now()}}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for i := range probes {
			select {
			case jobs <- i:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(done) }()
	for {
		select {
		case r, ok := <-done:
			if !ok {
				return observed
			}
			observed[r.index] = r.observation
		case <-ctx.Done():
			// Include already completed evidence without waiting for late checks.
			for {
				select {
				case r, ok := <-done:
					if !ok {
						return observed
					}
					observed[r.index] = r.observation
				default:
					return observed
				}
			}
		}
	}
}
