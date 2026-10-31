package subscription

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// Bump this when parsing changes. Stored source bytes can then be reinterpreted
// locally instead of forcing a new download. The containing file is private:
// raw content can contain credentials and must never appear in diagnostics.
const ParserVersion = 2

type Content struct {
	SourceID string `json:"source_id"`
	SHA256   string `json:"sha256"`
	Data     []byte `json:"data"`
}

type Snapshot struct {
	Contents []Content `json:"contents"`
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sourceID(s Source) string {
	raw, _ := json.Marshal(struct{ URL, File string }{s.URL, s.File})
	return digest(raw)
}

func normalizedSources(s Sources) (Sources, error) {
	// Copy maps/slices before normalizing so callers keep their input unchanged.
	s.Rules = append([]Source(nil), s.Rules...)
	if len(s.Rules) > 8 {
		return s, errors.New("too many subscription sources")
	}
	if err := normalize(&s.Nodes, "."); err != nil {
		return s, err
	}
	for i := range s.Rules {
		if err := normalize(&s.Rules[i], "."); err != nil {
			return s, err
		}
	}
	return s, nil
}

func (s Snapshot) index() (map[string][]byte, error) {
	if len(s.Contents) == 0 || len(s.Contents) > 9 {
		return nil, errors.New("invalid subscription content count")
	}
	byID := make(map[string][]byte, len(s.Contents))
	for _, c := range s.Contents {
		if len(c.SourceID) != 64 || len(c.Data) > 4<<20 || c.SHA256 != digest(c.Data) {
			return nil, errors.New("invalid subscription content digest or size")
		}
		if _, exists := byID[c.SourceID]; exists {
			return nil, errors.New("duplicate subscription content identity")
		}
		byID[c.SourceID] = c.Data
	}
	return byID, nil
}

// Fingerprint binds parsed results to content, parser version and interpretation
// options. Refresh interval and local network policy do not affect parsing.
func (s Snapshot) Fingerprint(sources Sources) (string, error) {
	sources, err := normalizedSources(sources)
	if err != nil {
		return "", err
	}
	byID, err := s.index()
	if err != nil {
		return "", err
	}
	sources.IntervalMinutes = 0
	ids := []string{}
	for _, src := range append([]Source{sources.Nodes}, sources.Rules...) {
		data, ok := byID[sourceID(src)]
		if !ok {
			return "", errors.New("subscription source content missing; run sync")
		}
		ids = append(ids, digest(data))
	}
	raw, _ := json.Marshal(struct {
		Parser  int
		Sources Sources
		Digests []string
	}{ParserVersion, sources, ids})
	return digest(raw), nil
}

// Parse performs no file or network I/O, including when mappings have changed.
func (s Snapshot) Parse(sources Sources) (Result, error) {
	sources, err := normalizedSources(sources)
	if err != nil {
		return Result{}, err
	}
	byID, err := s.index()
	if err != nil {
		return Result{}, err
	}
	return parseWith(context.Background(), sources, func(_ context.Context, src Source) ([]byte, error) {
		data, ok := byID[sourceID(src)]
		if !ok {
			return nil, errors.New("subscription source content missing; run sync")
		}
		return data, nil
	})
}

func FetchSnapshot(ctx context.Context, sources Sources) (Snapshot, Result, error) {
	return fetchSnapshotWith(ctx, sources, Read)
}

func fetchSnapshotWith(ctx context.Context, sources Sources, read func(context.Context, Source) ([]byte, error)) (Snapshot, Result, error) {
	sources, err := normalizedSources(sources)
	if err != nil {
		return Snapshot{}, Result{}, err
	}
	var snapshot Snapshot
	seen := map[string]bool{}
	for _, source := range append([]Source{sources.Nodes}, sources.Rules...) {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, Result{}, err
		}
		id := sourceID(source)
		if seen[id] {
			continue
		}
		data, err := read(ctx, source)
		if err != nil {
			return Snapshot{}, Result{}, err
		}
		if len(data) > 4<<20 {
			return Snapshot{}, Result{}, errors.New("subscription content too large")
		}
		seen[id] = true
		snapshot.Contents = append(snapshot.Contents, Content{SourceID: id, SHA256: digest(data), Data: append([]byte(nil), data...)})
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, Result{}, err
	}
	result, err := snapshot.Parse(sources)
	return snapshot, result, err
}
