//go:build windows

package app

import (
	"context"
	"errors"
	"testing"

	"netlaunch/internal/winnet"
	"netlaunch/internal/winservice"
)

type authSocketAbortFixture struct{ code int }

func authSocketFixture() (winservice.UserAuthNetworkBinding, winnet.Physical) {
	plan := winservice.UserAuthNetworkBinding{GUID: "{8B3AFCE7-975C-4164-A9B1-6B9BFBB4D032}", LUID: 1234, Index: 7, Address: "192.0.2.10", Gateway: "192.0.2.1", Generation: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	return plan, winnet.Physical{Adapter: winnet.Adapter{GUID: plan.GUID, LUID: plan.LUID, Index: plan.Index, Hardware: true, Up: true}, Address: plan.Address, Gateway: plan.Gateway}
}
func TestServiceAuthSocketChecksBeforeAndAfterBinding(t *testing.T) {
	plan, actual := authSocketFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queries, sets, reads := 0, 0, 0
	g, err := newServiceAuthSocketGuardWith(ctx, plan, cancel, serviceAuthSocketDependencies{
		discover: func() (winnet.Physical, error) { queries++; return actual, nil },
		set: func(fd uintptr, index uint32) error {
			sets++
			if fd != 10 || index != 7 {
				t.Fatal("C int fd or fixed interface altered")
			}
			return nil
		},
		get:   func(uintptr) (uint32, error) { reads++; return 7, nil },
		abort: func(int) { t.Fatal("valid binding aborted") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if g.Err() == nil {
		t.Fatal("missing callback proof accepted")
	}
	g.Protect(uintptr(0xfeed00000000000a))
	if g.Err() != nil || queries != 2 || sets != 1 || reads != 1 {
		t.Fatal("binding lacks independent verification", g.Err(), queries, sets, reads)
	}
}
func TestServiceAuthSocketFailureCannotReturnToConnect(t *testing.T) {
	for _, stage := range []string{"before_unknown", "before_identity", "set", "readback", "after_generation", "c_int_invalid", "abort_returns"} {
		t.Run(stage, func(t *testing.T) {
			plan, actual := authSocketFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			queries, aborted := 0, false
			g, err := newServiceAuthSocketGuardWith(ctx, plan, cancel, serviceAuthSocketDependencies{
				discover: func() (winnet.Physical, error) {
					queries++
					if stage == "before_unknown" {
						return winnet.Physical{}, errors.New("unknown")
					}
					a := actual
					if stage == "before_identity" || stage == "after_generation" && queries == 2 {
						a.Address = "192.0.2.11"
					}
					return a, nil
				},
				set: func(uintptr, uint32) error {
					if stage == "set" {
						return errors.New("unsupported")
					}
					return nil
				},
				get: func(uintptr) (uint32, error) {
					if stage == "readback" {
						return 8, nil
					}
					return 7, nil
				},
				abort: func(code int) {
					aborted = true
					if code != authSocketWorkerAbortCode {
						t.Fatal("unexpected exitcode")
					}
					if stage != "abort_returns" {
						panic(authSocketAbortFixture{code})
					}
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if stage == "abort_returns" {
				cancel()
			}
			reachedConnect := false
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("failed callback returned without terminating worker")
					}
				}()
				fd := uintptr(10)
				if stage == "c_int_invalid" {
					fd = uintptr(^uint32(0))
				}
				g.Protect(fd)
				reachedConnect = true
			}()
			if reachedConnect || !aborted || g.Err() == nil || ctx.Err() == nil {
				t.Fatal("failed binding escaped worker containment")
			}
		})
	}
}
