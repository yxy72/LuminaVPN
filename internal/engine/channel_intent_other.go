//go:build !windows

package engine

import (
	"errors"
	"netlaunch/internal/policy"
)

func SetChannels(string, policy.ChannelIntent) error {
	return errors.New("Windows desktop channel control unavailable")
}
