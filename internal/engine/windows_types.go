package engine

import (
	"netlaunch/internal/winnet"
	"netlaunch/internal/winwfp"
)

// WindowsState is serialized only on Windows; the shared status and policy
// types remain identical across platforms.
type WindowsState struct {
	BootID        string          `json:"boot_id"`
	PublicRun     string          `json:"public_run"`
	Physical      winnet.Physical `json:"physical"`
	VPNAdapter    winnet.Adapter  `json:"vpn_adapter"`
	Guard         *winwfp.Spec    `json:"guard,omitempty"`
	VPNAddress    winnet.Address  `json:"vpn_address"`
	TUNAdapter    winnet.Adapter  `json:"tun_adapter"`
	AdapterBefore []string        `json:"adapter_before"`
	LaunchToken   string          `json:"launch_token,omitempty"`
	Epoch         uint64          `json:"epoch"`
}
