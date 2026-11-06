package engine

import (
	"netlaunch/internal/platform"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winwfp"
	"time"
)

type OwnedAdapterIntent struct {
	Role    string            `json:"role"`
	Name    string            `json:"name"`
	Owner   platform.Identity `json:"owner"`
	Adapter *winnet.Adapter   `json:"adapter,omitempty"`
}

// WindowsState is serialized only on Windows; the shared status and policy
// types remain identical across platforms.
type WindowsState struct {
	AdapterIntents     []OwnedAdapterIntent `json:"adapter_intents,omitempty"`
	BootID             string               `json:"boot_id"`
	PublicRun          string               `json:"public_run"`
	Physical           winnet.Physical      `json:"physical"`
	VPNAdapter         winnet.Adapter       `json:"vpn_adapter"`
	Guard              *winwfp.Spec         `json:"guard,omitempty"`
	IPv6Guard          *winwfp.IPv6Spec     `json:"ipv6_guard,omitempty"`
	AuthExpires        time.Time            `json:"auth_expires,omitempty"`
	VPNAddress         winnet.Address       `json:"vpn_address"`
	TUNAdapter         winnet.Adapter       `json:"tun_adapter"`
	AdapterBefore      []string             `json:"adapter_before"`
	LaunchToken        string               `json:"launch_token,omitempty"`
	Epoch              uint64               `json:"epoch"`
	ValidationDeadline time.Time            `json:"validation_deadline,omitempty"`
}
