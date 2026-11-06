package winservice

import (
	p "netlaunch/internal/serviceprotocol"
	"time"
)

// Aliases are independent request envelopes backed by one restoration job.
// They live in the durable journal, so concurrent quit requests do not grow
// the in-memory queue or inherit another request's Kind/RequestID.
func (b *Broker) stopAlias(m p.Mutation, parent p.Operation) (p.Operation, error) {
	id, err := newID("op-")
	if err != nil {
		return p.Operation{}, err
	}
	now := time.Now()
	alias := p.Operation{ID: id, AliasOf: parent.ID, RequestID: m.RequestID, ProfileID: m.ProfileID, RunRef: parent.RunRef, Revision: parent.Revision, Kind: m.Kind, Phase: "waiting_for_restore", Created: now, Updated: now}
	if err = b.ledger.Save(alias); err != nil {
		return p.Operation{}, safeError("JOURNAL_UNAVAILABLE")
	}
	return b.resolveAlias(alias)
}
func (b *Broker) resolveAlias(alias p.Operation) (p.Operation, error) {
	if alias.AliasOf == "" {
		return alias, nil
	}
	var parent p.Operation
	if e := b.operations[alias.AliasOf]; e != nil {
		parent = e.operation
	} else if history, ok := b.ledger.(historicalLedger); ok {
		var present bool
		var err error
		parent, present, err = history.FindOperation(alias.AliasOf)
		if err != nil || !present {
			return p.Operation{}, safeError("JOURNAL_UNAVAILABLE")
		}
	}
	if parent.ID == "" || parent.AliasOf != "" || parent.ProfileID != alias.ProfileID || parent.RunRef != alias.RunRef {
		return p.Operation{}, safeError("JOURNAL_UNAVAILABLE")
	}
	alias.Phase = parent.Phase
	alias.Completed = parent.Completed
	alias.Restored = parent.Restored
	alias.Revision = parent.Revision
	alias.Error = parent.Error
	alias.FirstFailure = parent.FirstFailure
	alias.Updated = time.Now()
	if parent.Completed || parent.Error != nil {
		if b.ledger.Save(alias) != nil {
			setFailure(&alias, "JOURNAL_UNAVAILABLE")
			alias.Completed = false
			alias.Restored = false
		}
	}
	return alias, nil
}
