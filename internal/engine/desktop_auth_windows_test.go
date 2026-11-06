//go:build windows

package engine

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"netlaunch/internal/auth"
)

func TestDesktopAuthMissingOrExpiredDoesNotBlockTheBase(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		readErr, decodeErr, writeErr error
		want                         []string
		fatal                        bool
	}{
		{"missing", os.ErrNotExist, nil, nil, []string{"read"}, false},
		{"private_acl_failure", os.ErrPermission, nil, nil, []string{"read"}, true},
		{"expired_envelope", nil, errors.New("expired"), nil, []string{"read", "decode", "remove"}, false},
		{"undecryptable_envelope", nil, errors.New("wrong user"), nil, []string{"read", "decode", "remove"}, false},
		{"private_store_failure", nil, nil, os.ErrPermission, []string{"read", "decode", "write"}, true},
		{"valid_session", nil, nil, nil, []string{"read", "decode", "write", "remove"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var steps []string
			body := []byte("encrypted fixture")
			err := stageDesktopAuthWith(
				func() ([]byte, error) {
					steps = append(steps, "read")
					if tc.readErr != nil {
						return nil, tc.readErr
					}
					return body, nil
				},
				func([]byte) (auth.Session, error) {
					steps = append(steps, "decode")
					return auth.Session{}, tc.decodeErr
				},
				func(auth.Session) error { steps = append(steps, "write"); return tc.writeErr },
				func() error { steps = append(steps, "remove"); return nil },
			)
			if (err != nil) != tc.fatal || !reflect.DeepEqual(steps, tc.want) {
				t.Fatal(err, steps)
			}
			if tc.readErr == nil {
				for _, b := range body {
					if b != 0 {
						t.Fatal("staged auth bytes retained")
					}
				}
			}
		})
	}
}
