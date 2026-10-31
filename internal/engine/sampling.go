package engine

import (
	"context"
	"sync"
	"time"
)

type nodeSample struct {
	name  string
	delay int
}

// A false known result means the work was interrupted or not observed, rather
// than a measured node failure. Workers must honor their context.
func sampleNodes(parent context.Context, names []string, budget time.Duration, parallel int, probe func(context.Context, string) (delay int, known bool)) map[string]int {
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	if parallel < 1 {
		parallel = 1
	}
	jobs := make(chan string)
	results := make(chan nodeSample, len(names))
	var workers sync.WaitGroup
	for i := 0; i < parallel && i < len(names); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case name, ok := <-jobs:
					if !ok || ctx.Err() != nil {
						return
					}
					delay, known := probe(ctx, name)
					if known && ctx.Err() == nil {
						results <- nodeSample{name, delay}
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, name := range names {
			select {
			case jobs <- name:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()
	values := map[string]int{}
	for {
		select {
		case result, ok := <-results:
			if !ok {
				return values
			}
			values[result.name] = result.delay
		case <-ctx.Done():
			// Capture completed observations already published, without waiting
			// for interrupted workers or classifying the remainder as failures.
			for {
				select {
				case result, ok := <-results:
					if !ok {
						return values
					}
					values[result.name] = result.delay
				default:
					return values
				}
			}
		}
	}
}
