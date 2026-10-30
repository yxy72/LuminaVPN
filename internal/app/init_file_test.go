package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
)

func TestInitFromPortablePolicyIsPrivateAndDoesNotOverwrite(t *testing.T) {
	root := testutil.PrivateTempDir(t)
	source := filepath.Join(root, "portable.private.json")
	data := strings.ReplaceAll(Example, "gateway.corp.example.com", "private-fixture.example.com")
	if e := os.WriteFile(source, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	profile := filepath.Join(root, "profile")
	var output bytes.Buffer
	cli := CLI{Out: &output, Err: &output}
	if e := cli.Run([]string{"init", "--file", source, "--profile", profile}); e != nil {
		t.Fatal(e)
	}
	got, e := securefile.Read(filepath.Join(profile, "policy.json"), 1<<20, true)
	if e != nil || string(got) != data || strings.Contains(output.String(), "private-fixture") {
		t.Fatal("portable policy not preserved privately, or disclosed in output", e)
	}
	if e := cli.Run([]string{"init", "--file", source, "--profile", profile}); e == nil {
		t.Fatal("existing policy overwritten")
	}
	if _, e := os.Stat(filepath.Join(profile, "current.json")); !os.IsNotExist(e) {
		t.Fatal("initialization created a network run")
	}
}

func TestInvalidPortablePolicyLeavesNoProfile(t *testing.T) {
	for _, data := range []string{`{"private":"credential-value"}`, strings.Replace(Example, `"version": 1`, `"version": 1, "session": "credential-value"`, 1)} {
		root := testutil.PrivateTempDir(t)
		source := filepath.Join(root, "portable.private.json")
		os.WriteFile(source, []byte(data), 0600)
		profile := filepath.Join(root, "new-profile")
		var output bytes.Buffer
		e := (CLI{Out: &output, Err: &output}).Run([]string{"init", "--file", source, "--profile", profile})
		if e == nil || strings.Contains(e.Error()+output.String(), "credential-value") {
			t.Fatal("invalid policy accepted or disclosed")
		}
		if _, e := os.Stat(profile); !os.IsNotExist(e) {
			t.Fatal("invalid input modified profile")
		}
	}
}
