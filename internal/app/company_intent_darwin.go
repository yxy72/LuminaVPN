//go:build darwin

package app

import (
	"errors"
	"flag"
	"io"
	"os"

	"netlaunch/internal/engine"
)

func companyIntentEntry(args []string, output io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("native administrator authorization is required")
	}
	f := flag.NewFlagSet("_company-intent", flag.ContinueOnError)
	f.SetOutput(output)
	run := f.String("run", "", "exact active run directory")
	request := f.String("request-id", "", "company request identity")
	generation := f.Uint64("expected-generation", 0, "current applied channel generation")
	intent := f.String("company", "", "company intent, on or off")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *run == "" || (*intent != "on" && *intent != "off") {
		return errors.New("invalid native company intent request")
	}
	return engine.RequestDarwinCompanyChange(*run, *request, *generation, *intent == "on")
}
