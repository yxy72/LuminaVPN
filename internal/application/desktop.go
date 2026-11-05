// Package application exposes use cases shared with the CLI, without exposing
// raw profile, credentials, controller access or native recovery journals.
package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"netlaunch/internal/app"
	"netlaunch/internal/engine"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
)

type Error struct {
	Code      string
	Message   string
	Retryable bool
}

func (e *Error) Error() string               { return e.Message }
func unavailable(code, message string) error { return &Error{Code: code, Message: message} }

type Desktop struct {
	Profile, Runtime string
	Now              func() time.Time
}

func NewDesktop(profile, bundle string) (*Desktop, error) {
	if profile == "" {
		var err error
		profile, err = app.DefaultProfile()
		if err != nil {
			return nil, unavailable("PROFILE_UNAVAILABLE", "Local profile location unavailable.")
		}
	}
	var err error
	profile, err = filepath.Abs(profile)
	if err != nil {
		return nil, unavailable("PROFILE_UNAVAILABLE", "Local profile location unavailable.")
	}
	bundle, err = filepath.Abs(bundle)
	if err != nil {
		return nil, unavailable("RUNTIME_UNAVAILABLE", "Bundled runtime location unavailable.")
	}
	return &Desktop{Profile: profile, Runtime: bundle, Now: time.Now}, nil
}

func (d *Desktop) configured() bool {
	_, err := os.Lstat(filepath.Join(d.Profile, "policy.json"))
	return !errors.Is(err, os.ErrNotExist)
}

func timestamp(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}

type Profile struct {
	Configured         bool     `json:"configured"`
	ProfileName        string   `json:"profile_name"`
	PolicyValid        bool     `json:"policy_valid"`
	NodesAvailable     bool     `json:"nodes_available"`
	NodeCount          int      `json:"node_count"`
	Revision           *string  `json:"revision"`
	TransactionPending bool     `json:"transaction_pending"`
	Issues             []string `json:"issues"`
	ReadOnly           bool     `json:"read_only"`
}

func (d *Desktop) InspectProfile() Profile {
	p := Profile{Configured: d.configured(), ProfileName: "本机配置", Issues: []string{}, ReadOnly: true}
	if !p.Configured {
		p.Issues = append(p.Issues, "PROFILE_NOT_CONFIGURED")
		return p
	}
	if securefile.CheckDir(d.Profile) != nil {
		p.Issues = append(p.Issues, "PROFILE_PRIVATE_DIRECTORY_REQUIRED")
		return p
	}
	cfg, err := app.DesktopPolicy(d.Profile)
	if err != nil {
		p.Issues = append(p.Issues, "POLICY_INVALID")
		return p
	}
	p.PolicyValid = true
	revision := app.DesktopRevision(cfg)
	p.Revision = &revision
	p.TransactionPending, err = app.DesktopTransactionPending(d.Profile)
	if err != nil {
		p.Issues = append(p.Issues, "CONFIG_TRANSACTION_UNREADABLE")
	} else if p.TransactionPending {
		p.Issues = append(p.Issues, "CONFIG_TRANSACTION_PENDING")
	}
	nodes, err := app.DesktopNodes(d.Profile, cfg)
	if err != nil {
		p.Issues = append(p.Issues, "NODE_CACHE_UNAVAILABLE")
	} else {
		p.NodesAvailable = true
		p.NodeCount = len(nodes)
	}
	return p
}

type Channel struct {
	State        string  `json:"state"`
	Reason       string  `json:"reason"`
	CheckedAt    *string `json:"checked_at"`
	NextAction   string  `json:"next_action"`
	PathState    string  `json:"path_state"`
	ServiceState string  `json:"service_state"`
	ProbeScope   string  `json:"probe_scope,omitempty"`
}
type SavedStatus struct {
	Phase     string             `json:"phase"`
	Lifecycle string             `json:"lifecycle"`
	Updated   *string            `json:"updated"`
	LastReady *string            `json:"last_ready"`
	Personal  *string            `json:"personal"`
	Channels  map[string]Channel `json:"channels"`
}
type State struct {
	ProfileConfigured  bool        `json:"profile_configured"`
	RunRef             *string     `json:"run_ref"`
	Status             SavedStatus `json:"status"`
	SnapshotStale      bool        `json:"snapshot_stale"`
	SnapshotAgeSeconds *int64      `json:"snapshot_age_seconds"`
	RuntimeLiveness    string      `json:"runtime_liveness"`
	RecoveryRequired   bool        `json:"recovery_required"`
	StopRequested      bool        `json:"stop_requested"`
	ObservedAt         string      `json:"observed_at"`
}

func oneOf(value, fallback string, choices ...string) string {
	for _, choice := range choices {
		if value == choice {
			return value
		}
	}
	return fallback
}

var reasonCodes = []string{
	"not_checked", "stopped", "stopping", "recovery_failed", "authentication_required", "physical_network_unavailable", "company_check_failed", "generation_changed", "vpn_not_ready", "lease_unavailable", "no_verified_node", "selection_changed", "network_changed", "check_expired", "probe_budget_expired", "path_verified", "service_healthy", "http_status_rejected", "core_ingress_unavailable", "tcp_unavailable", "tls_certificate_invalid", "tls_failed", "tls_timeout", "http_response_missing", "http_write_failed", "path_probe_failed", "company_authorization_unavailable", "verification_budget_expired", "personal_verification_timeout", "pending_or_unclassified", "core_control_unavailable",
}
var nodeID = regexp.MustCompile(`^P[0-9]{3}$`)
var subscriptionRuleSource = regexp.MustCompile(`^subscriptions\.(nodes|rules\[[0-7]\])$`)

func (d *Desktop) GetState() State {
	now := d.Now()
	s := State{ProfileConfigured: d.configured(), RuntimeLiveness: "not_checked", ObservedAt: now.UTC().Format(time.RFC3339Nano), Status: SavedStatus{Phase: "not_started", Lifecycle: "idle", Channels: map[string]Channel{}}}
	for _, name := range []string{"company", "personal", "direct"} {
		s.Status.Channels[name] = Channel{State: "unknown", Reason: "not_checked", NextAction: "check_status", PathState: "unknown", ServiceState: "not_checked"}
	}
	if _, err := os.Lstat(d.Profile); errors.Is(err, os.ErrNotExist) {
		return s
	}
	if securefile.CheckDir(d.Profile) != nil {
		s.Status.Phase = "interrupted"
		s.RecoveryRequired = true
		s.SnapshotStale = true
		return s
	}
	run, raw, present, stop, err := app.DesktopSavedStatus(d.Profile)
	s.StopRequested = stop
	if run != "" {
		digest := sha256.Sum256([]byte(run))
		ref := "run-" + hex.EncodeToString(digest[:8])
		s.RunRef = &ref
	}
	tx, txErr := app.DesktopTransactionPending(d.Profile)
	s.RecoveryRequired = tx || txErr != nil
	if !present {
		return s
	}
	if err != nil {
		s.Status.Phase = "interrupted"
		s.Status.Lifecycle = "interrupted"
		s.RecoveryRequired = true
		s.SnapshotStale = true
		return s
	}
	raw = engine.RefreshStatus(raw, now)
	s.Status.Phase = oneOf(raw.Phase, "interrupted", "prepared", "preparing", "connecting", "reconnecting", "starting", "ready", "degraded", "authentication_required", "company_unavailable", "personal_unavailable", "network_unavailable", "stopping", "stopped", "recovery_failed")
	s.Status.Lifecycle = oneOf(raw.Lifecycle, "unknown", "starting", "running", "stopping", "stopped", "recovery_failed")
	s.Status.Updated, s.Status.LastReady = timestamp(raw.Updated), timestamp(raw.LastReady)
	if nodeID.MatchString(raw.Personal) {
		selected := raw.Personal
		s.Status.Personal = &selected
	}
	for _, name := range []string{"company", "personal", "direct"} {
		h, exists := raw.Channels[name]
		if !exists {
			continue
		}
		s.Status.Channels[name] = Channel{State: oneOf(h.State, "unknown", "ready", "unavailable", "unknown"), Reason: oneOf(h.Reason, "not_checked", reasonCodes...), CheckedAt: timestamp(h.CheckedAt), NextAction: oneOf(h.NextAction, "check_status", "wait_for_probe", "wait_for_selection", "wait_for_reconnect", "wait_for_renewal", "check_company", "check_personal", "check_direct", "check_runtime", "check_network", "check_service_expectation", "check_status", "run_auth", "run_down", "start"), PathState: oneOf(h.PathState, "unknown", "verified", "failed", "unknown"), ServiceState: oneOf(h.ServiceState, "not_checked", "healthy", "failed", "not_checked", "unknown"), ProbeScope: oneOf(h.ProbeScope, "", "system_tun", "mixed_ingress", "company_binding")}
	}
	if s.Status.Phase == "ready" {
		for _, channel := range s.Status.Channels {
			if channel.State != "ready" {
				s.Status.Phase = "degraded"
				break
			}
		}
	}
	if !raw.Updated.IsZero() && !now.Before(raw.Updated) {
		age := int64(now.Sub(raw.Updated) / time.Second)
		s.SnapshotAgeSeconds = &age
	}
	s.SnapshotStale = raw.Phase != "stopped" && raw.Phase != "prepared" && (raw.Updated.IsZero() || now.Before(raw.Updated) || now.Sub(raw.Updated) > 40*time.Second)
	s.RecoveryRequired = s.RecoveryRequired || s.Status.Phase == "interrupted" || raw.Phase == "recovery_failed" || raw.Phase == "stopping" || (stop && raw.Phase != "stopped")
	return s
}

type Node struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Selected bool   `json:"selected"`
}
type Nodes struct {
	Items          []Node `json:"items"`
	Total          int    `json:"total"`
	Offset         int    `json:"offset"`
	Limit          int    `json:"limit"`
	Inventory      string `json:"inventory"`
	SelectionScope string `json:"selection_scope"`
	Latency        string `json:"latency"`
}

func (d *Desktop) ListNodes(offset, limit int) (Nodes, error) {
	out := Nodes{Items: []Node{}, Offset: offset, Limit: limit, Inventory: "next_start", SelectionScope: "not_compared", Latency: "not_provided"}
	if offset < 0 || offset > 256 || limit < 1 || limit > 100 {
		return out, unavailable("INVALID_PARAMS", "Invalid node pagination bounds.")
	}
	if !d.configured() {
		return out, nil
	}
	if securefile.CheckDir(d.Profile) != nil {
		return out, unavailable("PROFILE_UNAVAILABLE", "Private local profile unavailable.")
	}
	cfg, err := app.DesktopPolicy(d.Profile)
	if err != nil {
		return out, unavailable("POLICY_INVALID", "Local policy is missing or invalid.")
	}
	nodes, err := app.DesktopNodes(d.Profile, cfg)
	if err != nil {
		return out, unavailable("NODE_CACHE_UNAVAILABLE", "Validated node cache unavailable; use the existing CLI to import or sync.")
	}
	out.Total = len(nodes)
	end := min(offset+limit, len(nodes))
	for i := offset; i < end; i++ {
		id, _ := nodes[i]["name"].(string)
		typ, _ := nodes[i]["type"].(string)
		if !nodeID.MatchString(id) {
			continue
		}
		// Generated Pxxx labels can refer to different nodes after a cache
		// update. The saved frozen run's label alone is not identity evidence.
		out.Items = append(out.Items, Node{ID: id, Name: id, Type: oneOf(typ, "unknown", "vless", "hysteria2"), Selected: false})
	}
	return out, nil
}

func (d *Desktop) Config(offset, limit int) (any, error) {
	if offset < 0 || offset > 50000 || limit < 1 || limit > 100 {
		return nil, unavailable("INVALID_PARAMS", "Invalid rule pagination bounds.")
	}
	empty := map[string]any{"revision": nil, "rules": []any{}, "total": 0, "offset": offset, "limit": limit, "static_only": true, "read_only": true}
	if !d.configured() {
		return empty, nil
	}
	if securefile.CheckDir(d.Profile) != nil {
		return nil, unavailable("PROFILE_UNAVAILABLE", "Private local profile unavailable.")
	}
	cfg, err := app.DesktopPolicy(d.Profile)
	if err != nil {
		return nil, unavailable("POLICY_INVALID", "Local policy is missing or invalid.")
	}
	rules, err := app.DesktopRules(d.Profile, cfg)
	if err != nil {
		return nil, unavailable("RULE_SOURCE_UNAVAILABLE", "Validated rule sources unavailable; cached subscription sources may need synchronization.")
	}
	projected := make([]policy.PlannedRule, 0, limit)
	end := min(offset+limit, len(rules))
	for i := offset; i < end; i++ {
		r := rules[i]
		if !subscriptionRuleSource.MatchString(r.Source) {
			r.Source = oneOf(r.Source, "subscription_cache", "company.domains", "company.cidrs", "personal.domains", "personal.cidrs", "probes", "personal_rules", "subscription_cache", "fake_ip_guard", "default")
		}
		projected = append(projected, r)
	}
	return map[string]any{"revision": app.DesktopRevision(cfg), "rules": projected, "total": len(rules), "offset": offset, "limit": limit, "static_only": true, "read_only": true}, nil
}

func (d *Desktop) Subscriptions() (any, error) {
	out := map[string]any{"configured": false, "sources": []any{}, "cache_available": false, "updated_at": nil, "next_start_only": true}
	if !d.configured() {
		return out, nil
	}
	if securefile.CheckDir(d.Profile) != nil {
		return nil, unavailable("PROFILE_UNAVAILABLE", "Private local profile unavailable.")
	}
	cfg, err := app.DesktopPolicy(d.Profile)
	if err != nil {
		return nil, unavailable("POLICY_INVALID", "Local policy is missing or invalid.")
	}
	summary, err := app.DesktopSubscriptions(d.Profile, cfg)
	if err != nil {
		return nil, unavailable("SUBSCRIPTION_SOURCE_UNAVAILABLE", "Private subscription source settings unavailable.")
	}
	out["configured"], out["cache_available"], out["updated_at"] = summary.Configured, summary.CacheAvailable, timestamp(summary.Updated)
	sources := []any{}
	for i, kind := range summary.SourceKinds {
		state := "unavailable"
		if summary.CacheAvailable {
			state = "cached"
		}
		sources = append(sources, map[string]any{"id": fmt.Sprintf("source-%d", i+1), "kind": kind, "state": state, "updated_at": timestamp(summary.Updated)})
	}
	out["sources"] = sources
	return out, nil
}

type Check struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	Message string `json:"message"`
}

func (d *Desktop) Environment(ctx context.Context) (any, error) {
	checks := []Check{}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := runtimebundle.Verify(d.Runtime); err == nil {
		checks = append(checks, Check{"runtime_bundle", "passed", "随包运行组件的平台与文件摘要校验通过。"})
	} else {
		checks = append(checks, Check{"runtime_bundle", "failed", "随包运行组件缺失，或未通过平台与摘要校验。"})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if platform.Supported() {
		checks = append(checks, Check{"native_lifecycle", "passed", "当前后端包含本机网络生命周期能力。"})
	} else {
		checks = append(checks, Check{"native_lifecycle", "warning", "当前后端仅支持离线维护。"})
	}
	p := d.InspectProfile()
	if p.PolicyValid {
		checks = append(checks, Check{"local_policy", "passed", "本机策略通过与 CLI 共用的校验。"})
	} else {
		checks = append(checks, Check{"local_policy", "warning", "请先通过现有 CLI 创建私有本机配置。"})
	}
	if p.NodesAvailable {
		checks = append(checks, Check{"node_cache", "passed", "已验证的本机节点库存可用。"})
	} else {
		checks = append(checks, Check{"node_cache", "warning", "已验证的本机节点缓存尚不可用。"})
	}
	interfaces, err := net.Interfaces()
	online := false
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			online = true
			break
		}
	}
	if err == nil && online {
		checks = append(checks, Check{"network_interface", "passed", "发现活动的非回环网卡；尚未验证物理路由。"})
	} else {
		checks = append(checks, Check{"network_interface", "warning", "暂未确认活动的非回环网卡。"})
	}
	checks = append(checks, Check{"network_conflicts", "not_checked", "连接前仍需通过现有 CLI doctor 检查代理、VPN 与路由冲突。"}, Check{"privileged_listeners", "not_checked", "尚未检查特权监听入口与网络进程的实际存活。"}, Check{"desktop_lifecycle", "not_checked", "本轮桌面预览仅提供读取，连接操作尚未开放。"})
	labels := map[string]string{"runtime_bundle": "运行组件", "native_lifecycle": "平台能力", "local_policy": "本机策略", "node_cache": "节点库存", "network_interface": "网络接口", "network_conflicts": "代理与路由冲突", "privileged_listeners": "特权入口检查", "desktop_lifecycle": "桌面连接能力"}
	projected := []any{}
	for _, check := range checks {
		projected = append(projected, map[string]any{"id": check.ID, "label": labels[check.ID], "state": check.State, "message": check.Message})
	}
	return map[string]any{"checked_at": d.Now().UTC().Format(time.RFC3339Nano), "checks": projected, "ready_for_start": false, "read_only": true}, nil
}

func (d *Desktop) Recovery() any {
	s := d.GetState()
	native := app.DesktopBuild().Capabilities.NativeLifecycle
	state := "not_needed"
	if s.RunRef != nil && s.Status.Phase != "stopped" {
		state = "available"
	}
	if s.RecoveryRequired {
		state = "unconfirmed"
	}
	instructions := []string{"使用现有 CLI 的停止与恢复入口，并指定同一份本机配置。", "确认停止并完成恢复前，请保留当前运行目录及其冻结恢复程序。", "关闭本轮桌面预览不会停止已经建立的网络连接。"}
	if !native {
		state = "unavailable"
		instructions[0] = "当前构建不提供网络停止与恢复；请使用创建该运行的原 CLI 及其独立恢复入口。"
	}
	return map[string]any{"required": s.RecoveryRequired, "run_ref": s.RunRef, "status": state, "stop_requested": s.StopRequested, "available": native && s.RunRef != nil, "read_only": true, "instructions": instructions}
}
