//go:build windows

package main

import (
	"errors"
	"netlaunch/internal/winnet"
	"os"
	"reflect"
	"testing"
)

func TestRecoveryBeforeCreationDoesNotInventAdapter(t *testing.T) {
	missing := func() (winnet.Adapter, error) { return winnet.Adapter{}, os.ErrNotExist }
	if err := confirmReleasedProbeAdapter(missing, missing, func(winnet.Adapter) error { t.Fatal("no creation was started"); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestInterruptedCreateCannotPassWithOnlyRequestedGUID(t *testing.T) {
	checked := false
	err := confirmReleasedProbeAdapter(func() (winnet.Adapter, error) { return winnet.Adapter{}, os.ErrNotExist }, func() (winnet.Adapter, error) { return winnet.Adapter{GUID: "requested"}, nil }, func(a winnet.Adapter) error {
		checked = true
		if a.GUID != "requested" {
			t.Fatal(a)
		}
		return nil
	})
	if err == nil || !checked {
		t.Fatal("partial creation was accepted or not diagnosed", err)
	}
}

func TestCompletePublicationStillRequiresNativeAbsence(t *testing.T) {
	for _, checkErr := range []error{nil, errors.New("present"), errors.New("API denied"), errors.New("identity reused")} {
		expected := winnet.Adapter{Index: 43, LUID: 123, GUID: "published"}
		err := confirmReleasedProbeAdapter(func() (winnet.Adapter, error) { return expected, nil }, func() (winnet.Adapter, error) { t.Fatal("must use full publication"); return winnet.Adapter{}, nil }, func(a winnet.Adapter) error {
			if !reflect.DeepEqual(a, expected) {
				t.Fatal(a)
			}
			return checkErr
		})
		if !errors.Is(err, checkErr) {
			t.Fatal(err, checkErr)
		}
	}
}
