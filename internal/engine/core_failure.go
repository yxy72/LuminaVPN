package engine

import "errors"

// Never retain response bodies or controller credentials in public diagnostics.
type coreFailure struct {
	code   string
	status int
	cause  error
}

func (e *coreFailure) Error() string { return e.code }
func (e *coreFailure) Unwrap() error { return e.cause }

func newCoreFailure(code string, cause error) error { return &coreFailure{code: code, cause: cause} }

// Only the pinned core's delay endpoint uses these statuses as target results.
// Other API routes, authentication errors and connection failures are unknown
// node health, not negative node measurements.
func delayTargetFailure(err error) bool {
	var failure *coreFailure
	return errors.As(err, &failure) && (failure.status == 503 || failure.status == 504)
}
