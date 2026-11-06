package winservice

import (
	"context"
	"time"

	p "netlaunch/internal/serviceprotocol"
)

func (b *Broker) submitAttachment(v VerifiedPrincipal, m p.Mutation, old Binding, lookupErr error) (p.Operation, error) {
	if lookupErr != nil || !v.Verified() || !v.ordinary || v.profileID != m.ProfileID || old.OwnerSID != v.sid || old.ExecutorSID != b.executorSID || old.ServiceInstance != b.instance || v.logonEpoch == "" || old.LogonEpoch == "" {
		return p.Operation{}, safeError("ACCESS_DENIED")
	}
	if authorize(v, old, b.executorSID, b.instance) == nil {
		return p.Operation{}, safeError("ALREADY_ATTACHED")
	}
	for _, entry := range b.operations {
		if entry.operation.Kind == p.AttachEnrollment && (entry.pending || entry.operation.Error == nil && entry.operation.Completed) && entry.operation.ProfileID == m.ProfileID && entry.attachSource == old && authorize(v, entry.binding, b.executorSID, b.instance) == nil {
			return entry.operation, nil
		}
	}
	rotator, ok := b.owners.(enrollmentRotator)
	if !ok {
		return p.Operation{}, safeError("ENROLLMENT_UNAVAILABLE")
	}
	target := old
	clearRunBinding(&target)
	target.PendingEnrollmentID = ""
	target.LogonSID = v.logonSID
	target.AuthenticationID = v.authenticationID
	target.SessionID = v.sessionID
	target.LogonEpoch = v.logonEpoch
	if old.PendingEnrollmentID != "" {
		repairer, ok := b.owners.(enrollmentRepairer)
		if !ok {
			return p.Operation{}, safeError("ENROLLMENT_UNAVAILABLE")
		}
		planned, planErr := repairer.PendingTarget(old)
		if planErr != nil || authorize(v, planned, b.executorSID, b.instance) != nil {
			return p.Operation{}, safeError("LOGIN_TRANSFER_PENDING")
		}
		target = planned
	}
	retired, err := rotator.Retired(target)
	if err != nil || retired {
		return p.Operation{}, safeError("LOGIN_SESSION_RETIRED")
	}
	if id := b.attaching[m.ProfileID]; id != "" {
		e := b.operations[id]
		if e != nil && authorize(v, e.binding, b.executorSID, b.instance) == nil {
			return e.operation, nil
		}
		return p.Operation{}, safeError("LOGIN_TRANSFER_PENDING")
	}
	b.pruneCompleted()
	if len(b.operations) >= 1032 {
		return p.Operation{}, safeError("PRIORITY_OPERATION_LIMIT")
	}
	peer, err := v.retained()
	if err != nil {
		return p.Operation{}, safeError("CALLER_TOKEN_UNAVAILABLE")
	}
	id, err := newID("op-")
	if err != nil {
		peer.Close()
		return p.Operation{}, err
	}
	now := time.Now()
	op := p.Operation{ID: id, RequestID: m.RequestID, ProfileID: m.ProfileID, RunRef: old.RunRef, Revision: old.Revision, Kind: p.AttachEnrollment, Phase: "restoring_prior_enrollment", Created: now, Updated: now}
	if err = b.ledger.Save(op); err != nil {
		peer.Close()
		return p.Operation{}, safeError("JOURNAL_UNAVAILABLE")
	}
	b.operations[id] = &entry{operation: op, binding: target, pending: true, done: make(chan struct{}), attachSource: old}
	if b.attaching == nil {
		b.attaching = map[string]string{}
	}
	b.attaching[m.ProfileID] = id
	b.generations[m.ProfileID]++
	b.stopping[m.ProfileID] = true
	if active := b.active[m.ProfileID]; active != nil {
		active.cancel()
	}
	waits := []<-chan struct{}{}
	for other, entry := range b.operations {
		if other != id && entry.binding.ProfileID == m.ProfileID && entry.pending {
			waits = append(waits, entry.done)
		}
	}
	go b.performAttachment(id, peer, old, target, waits)
	return op, nil
}
func (b *Broker) performAttachment(id string, peer VerifiedPrincipal, old, target Binding, waits []<-chan struct{}) {
	defer peer.Close()
	defer b.finishWork(id)
	ctx, cancel := context.WithTimeout(b.ctx, 2*time.Minute)
	defer cancel()
	failed := func(code string) {
		b.mu.Lock()
		delete(b.attaching, old.ProfileID)
		b.mu.Unlock()
		b.failWork(id, code)
	}
	if backend, ok := b.backend.(interface {
		BeginEnrollmentBarrier(context.Context, Binding) error
	}); ok {
		if backend.BeginEnrollmentBarrier(ctx, old) != nil {
			failed("AUTH_WORKER_EXIT_UNCONFIRMED")
			return
		}
	}
	for _, wait := range waits {
		select {
		case <-wait:
		case <-ctx.Done():
			failed("ENROLLMENT_DRAIN_INCOMPLETE")
			return
		}
	}
	b.mu.Lock()
	current, err := b.owners.Lookup(old.ProfileID)
	b.mu.Unlock()
	if err != nil || !sameEnrollment(current, old) {
		failed("OWNERSHIP_UNAVAILABLE")
		return
	}
	if current.PendingEnrollmentID != "" {
		b.mu.Lock()
		rotated, rotateErr := b.owners.(enrollmentRotator).Rotate(current, target)
		b.mu.Unlock()
		if rotateErr != nil {
			failed("ENROLLMENT_PERSISTENCE_FAILED")
			return
		}
		b.completeAttachment(ctx, id, old, rotated, failed)
		return
	}
	completion, err := b.backend.StopAndRestore(ctx, AuthorizedOperation{binding: current, systemStop: true, mutation: p.Mutation{Kind: p.TakeoverStop, ProfileID: current.ProfileID, RunRef: current.RunRef, Stop: &p.StopPayload{}}}, func(Progress) {})
	if err != nil || !completion.Restored {
		failed("RESTORE_INCOMPLETE")
		return
	}
	b.mu.Lock()
	latest, lookupErr := b.owners.Lookup(old.ProfileID)
	if lookupErr != nil || !sameEnrollment(latest, current) || latest.RunRef != current.RunRef {
		b.mu.Unlock()
		failed("OWNERSHIP_UNAVAILABLE")
		return
	}
	clearRunBinding(&latest)
	latest.LastRestorationID = completion.RestorationID
	latest.Revision++
	if completion.Revision > latest.Revision {
		latest.Revision = completion.Revision
	}
	if b.owners.Save(latest) != nil {
		b.mu.Unlock()
		failed("OWNERSHIP_UNAVAILABLE")
		return
	}
	target.Revision = latest.Revision + 1
	target.LastRestorationID = latest.LastRestorationID
	rotated, rotateErr := b.owners.(enrollmentRotator).Rotate(latest, target)
	b.mu.Unlock()
	if rotateErr != nil {
		failed("ENROLLMENT_PERSISTENCE_FAILED")
		return
	}
	b.completeAttachment(ctx, id, old, rotated, failed)
}
func (b *Broker) completeAttachment(ctx context.Context, id string, old, rotated Binding, failed func(string)) {
	if backend, ok := b.backend.(interface {
		EnrollmentRotated(context.Context, Binding) error
	}); ok {
		if backend.EnrollmentRotated(ctx, rotated) != nil {
			failed("BACKEND_UNAVAILABLE")
			return
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.operations[id]
	e.binding = rotated
	e.operation.Completed = true
	e.operation.Restored = true
	e.operation.Phase = "enrollment_attached"
	e.operation.Revision = rotated.Revision
	e.operation.Updated = time.Now()
	if b.ledger.Save(e.operation) != nil {
		setFailure(&e.operation, "JOURNAL_UNAVAILABLE")
		e.operation.Completed = false
		return
	}
	delete(b.attaching, old.ProfileID)
	b.stopping[old.ProfileID] = false
	b.ownedProfile = ""
}
