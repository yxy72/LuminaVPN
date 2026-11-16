package application

import (
	"context"
	"errors"
	"os"

	"netlaunch/internal/platform"
	"netlaunch/internal/securefile"
)

func (w *localWorkspace) macConflictObservation() (uint64, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := w.network
	if w.closed || w.active != nil {
		return n.revision, false
	}
	profile := w.commands.Profile
	if _, err := os.Lstat(profile); !errors.Is(err, os.ErrNotExist) && securefile.CheckDir(profile) != nil {
		return n.revision, false
	}
	n.observe(profile)
	// A saved stopped report permits an observation without attributing any
	// remaining native resources or treating the report as a recovery receipt.
	return n.revision, !n.lost.present && (!n.current.present || n.stoppedReport() && !n.current.status.TakeoverActive)
}

func (w *localWorkspace) checkMacEnvironment(ctx context.Context, discover func() (platform.Network, error), conflicts func(platform.Network) error, foreignVPN func() bool) (Check, error) {
	const id = "network_conflicts"
	pending := Check{id, "not_checked", "当前运行或恢复状态尚未确认，暂不判断代理、VPN 与路由冲突。"}
	if err := ctx.Err(); err != nil {
		return Check{}, err
	}
	revision, idle := w.macConflictObservation()
	if !idle {
		return pending, nil
	}
	validate := func() (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		current, idle := w.macConflictObservation()
		return idle && current == revision, nil
	}
	network, err := discover()
	if valid, err := validate(); err != nil || !valid {
		return pending, err
	}
	if err != nil {
		return Check{id, "warning", "未能确认有可接管的活动物理 IPv4 网络，冲突检查暂未完成。"}, nil
	}
	err = conflicts(network)
	if valid, err := validate(); err != nil || !valid {
		return pending, err
	}
	switch {
	case errors.Is(err, platform.ErrSystemProxyConflict):
		return Check{id, "failed", "检测到已启用的系统代理或 PAC。"}, nil
	case errors.Is(err, platform.ErrTunnelDefaultConflict):
		return Check{id, "failed", "检测到有隧道占用 IPv4 默认路由或分段默认路由。"}, nil
	case err != nil:
		return Check{id, "warning", "未能读取系统代理或路由状态，冲突检查暂未完成。"}, nil
	}
	vpnRunning := foreignVPN()
	if valid, err := validate(); err != nil || !valid {
		return pending, err
	}
	if vpnRunning {
		return Check{id, "failed", "检测到正在运行的 OpenConnect。"}, nil
	}
	return Check{id, "passed", "本次检查未发现系统代理、OpenConnect 或 IPv4 默认路由冲突。"}, nil
}
