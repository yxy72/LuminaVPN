package main

import (
	"fmt"
	"netlaunch/internal/app"
	"netlaunch/internal/desktopbridge"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "desktop" {
		if err := desktopbridge.Run(os.Args[2:], os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "NetLaunch: desktop bridge unavailable")
			os.Exit(1)
		}
		return
	}
	if e := (app.CLI{Out: os.Stdout, Err: os.Stderr}).Run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "NetLaunch:", e)
		os.Exit(1)
	}
}
