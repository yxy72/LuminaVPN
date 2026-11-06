//go:build windows && windows_client

package main

import (
	"fmt"
	"os"

	"netlaunch/internal/app"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "A fixed user workspace action is required.")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "--workspace-worker":
		err = app.WorkspaceWorker(os.Stdin, os.Stdout)
	case "--snapshot-worker":
		err = app.ServiceUserSnapshot(os.Stdin, os.Stdout)
	case "--auth-worker":
		err = app.ServiceUserAuthenticate(os.Stdin, os.Stdout)
	default:
		fmt.Fprintln(os.Stderr, "A fixed user worker action is required.")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "The fixed user action could not be completed.")
		os.Exit(1)
	}
}
