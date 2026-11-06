package engine

import "netlaunch/internal/policy"

func currentIntent(s State) policy.ChannelIntent {
	if s.DesiredChannels == nil {
		return s.Manifest.InitialChannels()
	}
	return *s.DesiredChannels
}
