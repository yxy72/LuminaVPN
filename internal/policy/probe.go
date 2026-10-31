package policy

import "fmt"

// Existing personal probes check service responses; company/direct probes
// check paths. Explicit purpose overrides this compatibility default everywhere.
func (p Probe) EffectivePurpose() string {
	if p.Purpose != "" {
		return p.Purpose
	}
	if p.Channel == "personal" {
		return "service"
	}
	return "path"
}

func (p Probe) AcceptsStatus(code int) bool {
	if code < 200 || code > 599 {
		return false
	}
	if p.EffectivePurpose() == "path" {
		return true
	}
	if p.EffectivePurpose() != "service" {
		return false
	}
	if len(p.ExpectedStatus) == 0 {
		return code < 400
	}
	for _, expected := range p.ExpectedStatus {
		if code == expected {
			return true
		}
	}
	return false
}

func (p Probe) validatePurpose(field string) error {
	if p.EffectivePurpose() != "path" && p.EffectivePurpose() != "service" {
		return fieldError(field+".purpose", "expected path or service")
	}
	if len(p.ExpectedStatus) > 32 || (len(p.ExpectedStatus) > 0 && p.EffectivePurpose() != "service") {
		return fieldError(field+".expected_status", "up to 32 explicit status codes are allowed for service probes only")
	}
	seen := map[int]bool{}
	for index, code := range p.ExpectedStatus {
		if code < 200 || code > 599 || seen[code] {
			return fieldError(fmt.Sprintf("%s.expected_status[%d]", field, index), "expected a unique HTTP status from 200 through 599")
		}
		seen[code] = true
	}
	return nil
}
