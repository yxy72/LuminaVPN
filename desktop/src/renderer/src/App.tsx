import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowRight,
  Check,
  ChevronLeft,
  ChevronRight,
  Clock3,
  FileCheck2,
  FolderOpen,
  Globe2,
  Info,
  LayoutGrid,
  Network,
  Power,
  RefreshCw,
  Route,
  Search,
  Settings2,
  ShieldCheck,
  Sparkles,
  Unplug,
  Wifi,
  X,
} from "lucide-react";
import type {
  Channel,
  ChannelName,
  Config,
  Environment,
  Hello,
  LuminaAPI,
  Nodes,
  Profile,
  Recovery,
  State,
  Subscriptions,
} from "../../../protocol/types";
import { currentChannels, elapsedLabel, timeLabel } from "./evidence";
import { EnvironmentChecks } from "./environment";
import { ClientWorkspace } from "./ClientWorkspace";

declare global {
  interface Window {
    lumina: LuminaAPI;
  }
}

type Page = "overview" | "nodes" | "rules" | "diagnostics" | "settings";
type Data = {
  hello: Hello | null;
  state: State | null;
  profile: Profile | null;
  nodes: Nodes | null;
  config: Config | null;
  subscriptions: Subscriptions | null;
  recovery: Recovery | null;
};
const emptyData: Data = {
  hello: null,
  state: null,
  profile: null,
  nodes: null,
  config: null,
  subscriptions: null,
  recovery: null,
};
const channelNames: Record<string, string> = {
  company: "公司 VPN",
  personal: "个人代理",
  direct: "本机直连",
  reject: "拒绝访问",
};
const reasonNames: Record<string, string> = {
  not_checked: "尚未收到检查证据",
  path_verified: "配置目标的路径已验证",
  service_healthy: "配置的服务状态符合预期",
  check_expired: "检查证据已过期，等待复核",
  stopped: "运行已停止",
  stopping: "正在停止",
  authentication_required: "需要完成公司认证",
  vpn_not_ready: "等待公司 VPN 就绪",
  no_verified_node: "暂无通过验证的个人节点",
  http_status_rejected: "路径可达，服务状态未符合预期",
  probe_budget_expired: "本轮检查未完成",
  recovery_failed: "恢复尚未完成",
  physical_network_unavailable: "物理网络不可用",
  company_check_failed: "公司通道检查未通过",
  generation_changed: "VPN 已变化，等待重新检查",
  selection_changed: "节点已变化，等待重新检查",
  network_changed: "网络已变化，等待重新检查",
  lease_unavailable: "等待公司 DNS 租约更新",
  tls_certificate_invalid: "TLS 证书检查未通过",
  tcp_unavailable: "目标连接不可用",
  core_unavailable: "核心控制接口不可用",
  core_ingress_unavailable: "代理入口尚不可用",
};
const sourceNames: Record<string, string> = {
  "company.domains": "公司白名单",
  "company.cidrs": "公司网段",
  "personal.domains": "个人固定目标",
  "personal.cidrs": "个人固定网段",
  personal_rules: "本地覆盖",
  probes: "直连检查目标",
  default: "默认出口",
  fake_ip_guard: "地址保护",
};
const modeNames: Record<string, string> = {
  darwin: "macOS",
  macos_native: "macOS · Native",
  windows_home: "Windows · Home",
  windows_validation: "Windows · Validation",
  windows_offline: "Windows · Offline",
  windows_client: "Windows · 日常客户端",
  windows_client_validation: "Windows · 限时验证客户端",
  offline: "离线维护",
  native: "原生运行",
};
const platformNames: Record<string, string> = {
  darwin: "macOS",
  win32: "Windows",
  windows: "Windows",
  linux: "Linux",
};
const phaseNames: Record<string, string> = {
  stopped: "连接已停止",
  idle: "尚未建立连接",
  prepared: "运行已准备",
  starting: "正在启动",
  preparing: "正在准备",
  authentication_required: "等待公司认证",
  reconnecting: "正在重新连接",
  stopping: "正在停止",
  recovery_failed: "恢复尚未完成",
  network_unavailable: "网络暂不可用",
  company_unavailable: "公司通道暂不可用",
  degraded: "部分通道待确认",
};

function errorMessage(error: unknown): string {
  const code =
    typeof error === "object" && error !== null && "code" in error
      ? String(error.code)
      : "";
  return (
    (
      {
        PROFILE_INVALID: "当前配置无法读取或校验，请通过本地配置入口检查。",
        PROFILE_MISSING: "尚未找到本地配置，可以选择已有配置目录。",
        CONFIG_INVALID: "规则配置尚不可用，请检查本地配置。",
        BACKEND_UNAVAILABLE: "控制接口暂不可用，已保留最近一次状态。",
        BRIDGE_DISCONNECTED: "控制接口已断开，已保留最近一次状态。",
        CONTROL_UNAVAILABLE: "控制接口暂不可用，已保留最近一次状态。",
        CONTROL_DISCONNECTED: "控制接口已断开，已保留最近一次状态。",
        READ_TIMEOUT: "本次读取超时，已保留最近一次状态，请刷新后重试。",
        PROFILE_UNAVAILABLE: "本地配置暂不可读取，请检查目录与访问权限。",
        POLICY_INVALID: "策略配置未通过校验，请使用本地配置入口检查。",
        RULE_SOURCE_UNAVAILABLE: "规则来源缓存暂不可用，请使用已有 CLI 同步后刷新。",
        NODE_CACHE_UNAVAILABLE: "节点缓存暂不可用，请使用已有 CLI 导入或同步后刷新。",
        PROFILE_BUSY: "当前配置仍有活动或未确认的运行，请先通过独立恢复入口停止并确认，再切换配置。",
        PROFILE_NOT_ENROLLED: "此目录未登记到后台服务，已保留原配置目录。可在设置中恢复默认配置目录。",
        PROFILE_MISMATCH: "后台登记与目录标识不一致，已保留原配置目录。",
        PROFILE_RECOVERY_NOT_REQUIRED: "当前目录没有明确的未登记错误，不能通过此入口切换默认目录。",
      } as Record<string, string>
    )[code] ?? "读取未完成，请刷新后重试。"
  );
}

function useData() {
  const [data, setData] = useState<Data>(emptyData);
  const [control, setControl] = useState<
    "connecting" | "available" | "unavailable"
  >("connecting");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const generation = useRef(0);
  const mounted = useRef(true);
  const nodeOffset = useRef(0);
  const ruleOffset = useRef(0);
  const pollBusy = useRef(false);

  const loadInventory = useCallback(async () => {
    const current = generation.current;
    const result = await Promise.allSettled([
      window.lumina.listNodes({ offset: nodeOffset.current, limit: 100 }),
      window.lumina.getConfig({ offset: ruleOffset.current, limit: 100 }),
      window.lumina.subscriptionsSummary(),
      window.lumina.describeRecovery(),
    ]);
    if (!mounted.current || generation.current !== current) return;
    setData((previous) => ({
      ...previous,
      nodes: result[0].status === "fulfilled" ? result[0].value : null,
      config: result[1].status === "fulfilled" ? result[1].value : null,
      subscriptions: result[2].status === "fulfilled" ? result[2].value : null,
      recovery: result[3].status === "fulfilled" ? result[3].value : null,
    }));
  }, []);

  const refresh = useCallback(
    async (full = false) => {
      if (pollBusy.current || !window.lumina) return;
      pollBusy.current = true;
      if (full) setLoading(true);
      const current = generation.current;
      try {
        if (!full) {
          try {
            const state = await window.lumina.getState();
            if (!mounted.current || generation.current !== current) return;
            setData((previous) => ({ ...previous, state }));
            setControl("available");
            setError(null);
          } catch (readError) {
            if (!mounted.current || generation.current !== current) return;
            setControl("unavailable");
            setError(errorMessage(readError));
          }
          return;
        }
        const result = await Promise.allSettled([
          window.lumina.hello(),
          window.lumina.getState(),
          window.lumina.inspectProfile(),
        ]);
        if (!mounted.current || generation.current !== current) return;
        const hello = result[0],
          state = result[1],
          profile = result[2];
        if (hello.status === "fulfilled" && state.status === "fulfilled") {
          setData((previous) => ({
            ...previous,
            hello: hello.value,
            state: state.value,
            profile:
              profile.status === "fulfilled" ? profile.value : previous.profile,
          }));
          setControl("available");
          setError(
            profile.status === "rejected" ? errorMessage(profile.reason) : null,
          );
          if (full) await loadInventory();
        } else {
          setControl("unavailable");
          const failed =
            state.status === "rejected"
              ? state
              : hello.status === "rejected"
                ? hello
                : null;
          setError(errorMessage(failed?.reason));
        }
      } finally {
        pollBusy.current = false;
        if (mounted.current) setLoading(false);
      }
    },
    [loadInventory],
  );

  useEffect(() => {
    mounted.current = true;
    if (!window.lumina) {
      setControl("unavailable");
      setError("请在 LuminaVPN 桌面应用中打开界面，以读取本机状态。");
      return () => {
        mounted.current = false;
      };
    }
    void refresh(true);
    const timer = window.setInterval(() => {
      void refresh();
    }, 2000);
    return () => {
      mounted.current = false;
      window.clearInterval(timer);
    };
  }, [refresh]);

  const chooseProfile = async (restoreDefault = false) => {
    if (!window.lumina) return;
    setLoading(true);
    try {
      const profile = await (restoreDefault ? window.lumina.restoreDefaultProfile() : window.lumina.chooseProfile());
      if (!profile) return;
      generation.current++;
      nodeOffset.current = 0;
      ruleOffset.current = 0;
      setData({ ...emptyData, profile });
      setError(null);
      // A profile switch changes the bridge session. Wait for an older read to
      // finish before polling; its result is fenced by the local generation.
      while (pollBusy.current)
        await new Promise((resolve) => window.setTimeout(resolve, 30));
      await refresh(true);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  };

  const loadNodes = async (offset: number) => {
    nodeOffset.current = Math.max(0, offset);
    setLoading(true);
    const current = generation.current;
    try {
      const nodes = await window.lumina.listNodes({
        offset: nodeOffset.current,
        limit: 100,
      });
      if (generation.current === current)
        setData((previous) => ({ ...previous, nodes }));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  };

  const loadRules = async (offset: number) => {
    ruleOffset.current = Math.max(0, offset);
    setLoading(true);
    const current = generation.current;
    try {
      const config = await window.lumina.getConfig({
        offset: ruleOffset.current,
        limit: 100,
      });
      if (generation.current === current)
        setData((previous) => ({ ...previous, config }));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  };

  return {
    data,
    control,
    error,
    loading,
    refresh,
    chooseProfile,
    loadNodes,
    loadRules,
  };
}

function Badge({
  children,
  tone = "",
  dot = false,
}: {
  children: React.ReactNode;
  tone?: string;
  dot?: boolean;
}) {
  return (
    <span className={`tag ${tone}`}>
      {dot && <i className={`dot ${tone === "green" ? "" : tone || "dim"}`} />}
      {children}
    </span>
  );
}
function Header({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  children?: React.ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div className="actions">{children}</div>
    </header>
  );
}
function Empty({
  title,
  text,
  children,
}: {
  title: string;
  text: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="empty">
      <FolderOpen size={25} strokeWidth={1.3} />
      <h3>{title}</h3>
      <p>{text}</p>
      {children}
    </div>
  );
}
function PanelHead({
  children,
  icon: Icon,
  after,
}: {
  children: React.ReactNode;
  icon?: React.ElementType;
  after?: React.ReactNode;
}) {
  return (
    <div className="panel-head">
      <h2>
        {Icon && <Icon size={15} strokeWidth={1.5} />}
        {children}
      </h2>
      {after}
    </div>
  );
}
function RefreshButton({
  loading,
  onClick,
  children = "刷新展示",
}: {
  loading: boolean;
  onClick: () => void;
  children?: React.ReactNode;
}) {
  return (
    <button className="btn" onClick={onClick} disabled={loading}>
      <RefreshCw size={13} className={loading ? "spin" : ""} />
      {children}
    </button>
  );
}
function stateLabel(channel: Channel): string {
  return channel.state === "ready"
    ? "已验证"
    : channel.state === "unavailable"
      ? "不可用"
      : channel.reason === "check_expired"
        ? "已过期"
        : "待确认";
}
function pathLabel(value: string) {
  return value === "verified"
    ? "路径已验证"
    : value === "failed"
      ? "路径未通过"
      : "路径待确认";
}
function serviceLabel(value: string) {
  return value === "healthy"
    ? "符合预期"
    : value === "failed"
      ? "服务未通过"
      : value === "not_checked"
        ? "服务未检查"
        : "服务待确认";
}

function ChannelCard({
  name,
  channel,
  now,
}: {
  name: ChannelName;
  channel: Channel;
  now: number;
}) {
  const Icon =
    name === "company" ? ShieldCheck : name === "personal" ? Globe2 : Wifi;
  const title = name === "company" ? "公司网络" : channelNames[name];
  return (
    <section
      className="channel"
      aria-label={`${title}：${stateLabel(channel)}`}
    >
      <div className="channel-top">
        <span className="channel-icon">
          <Icon size={18} strokeWidth={1.5} />
        </span>
        <span className={`channel-state ${channel.state}`}>
          <i
            className={`dot ${channel.state === "ready" ? "" : channel.state === "unavailable" ? "danger" : "dim"}`}
          />
          {stateLabel(channel)}
        </span>
      </div>
      <h3>{title}</h3>
      <p>
        {reasonNames[channel.reason] ??
          (channel.state === "ready"
            ? "最近的配置目标检查通过"
            : "等待有效的通道检查")}
      </p>
      <div className="channel-bottom">
        <span>{pathLabel(channel.path_state)}</span>
        <b>{serviceLabel(channel.service_state)}</b>
      </div>
      <div className="channel-bottom">
        <span>最后检查</span>
        <b title={channel.checked_at ?? undefined}>
          {elapsedLabel(channel.checked_at, now)}
        </b>
      </div>
    </section>
  );
}

function Overview({
  data,
  now,
  control,
  go,
  loading,
  refresh,
}: {
  data: Data;
  now: number;
  control: string;
  go: (page: Page) => void;
  loading: boolean;
  refresh: () => void;
}) {
  const channels = currentChannels(data.state, now);
  const verified = Object.values(channels).filter(
    (c) => c.state === "ready",
  ).length;
  const allReady = verified === 3;
  const headline =
    control === "unavailable"
      ? "控制接口已断开"
      : !data.profile?.configured
        ? "等待本地配置"
        : !data.state?.run_ref
          ? "尚未建立连接"
          : data.state?.recovery_required
            ? "需要确认恢复"
            : allReady
              ? "最近检查已通过"
              : (phaseNames[data.state?.status.phase ?? ""] ??
                "通道状态待确认");
  return (
    <>
      <Header
        eyebrow="YOUR NETWORK, IN ORDER."
        title="连接工作，也连接生活。"
        description="公司资源、个人代理与本机直连，各走各的路。"
      >
        <span className="small-note">
          {data.state
            ? `读取于 ${timeLabel(data.state.observed_at)}`
            : "等待本地状态"}
        </span>
      </Header>
      <section className="hero">
        <div className="connection">
          <div
            className={`power ${allReady && control === "available" ? "" : "unknown"}`}
          >
            <Power size={31} strokeWidth={1.4} />
            <span
              className={`pulse ${allReady && control === "available" ? "ready" : ""}`}
            />
          </div>
          <div>
            <div className="kicker">LUMINA CONNECTION</div>
            <h2>{headline}</h2>
            <div className="sub">
              <i className={`dot ${allReady ? "" : "dim"}`} />
              {data.state?.run_ref
                ? `${verified} / 3 通道具有新鲜成功证据`
                : "读取本机状态，尚未开放桌面连接"}
            </div>
            <div className="connection-actions">
              <button
                className="btn primary"
                disabled
                title="探针隔离、启动取消和恢复边界完成后开放"
              >
                <Power size={13} />
                连接网络
              </button>
            </div>
          </div>
        </div>
        <div className="hero-meta">
          <div className="meta-row">
            <span>保存的节点</span>
            <strong title={data.state?.status.personal ?? undefined}>
              <Globe2 size={13} />
              {data.state?.status.personal || "尚未选择"}
            </strong>
          </div>
          <div className="meta-row">
            <span>当前配置</span>
            <strong>
              {data.profile?.configured
                ? data.profile.profile_name
                : "尚未配置"}
              <Badge>本地</Badge>
            </strong>
          </div>
          <div className="meta-row">
            <span>进程存活</span>
            <strong>尚未检查</strong>
          </div>
          <div className="meta-row">
            <span>桌面版本</span>
            <strong>只读工程预览</strong>
          </div>
        </div>
      </section>
      <div className="channel-grid">
        {(["company", "personal", "direct"] as ChannelName[]).map((name) => (
          <ChannelCard
            key={name}
            name={name}
            channel={channels[name]}
            now={now}
          />
        ))}
      </div>
      <div className="bottom-grid">
        <section className="panel">
          <PanelHead
            icon={Route}
            after={
              <button className="link-btn" onClick={() => go("rules")}>
                查看规则
                <ArrowRight size={12} />
              </button>
            }
          >
            分流边界
          </PanelHead>
          <div className="route-list">
            {[
              ["明确授权的公司目标", "公司 VPN"],
              ["配置的个人目标", "个人代理"],
              ["其余目标", "本机直连"],
            ].map(([target, outlet]) => (
              <div className="route-line" key={target}>
                <code>{target}</code>
                <ArrowRight className="route-arrow" size={12} />
                <Badge>{outlet}</Badge>
              </div>
            ))}
          </div>
        </section>
        <section className="panel">
          <PanelHead
            icon={Clock3}
            after={
              <button className="link-btn" onClick={refresh} disabled={loading}>
                <RefreshCw size={12} className={loading ? "spin" : ""} />
                刷新
              </button>
            }
          >
            最近状态
          </PanelHead>
          <div className="activity">
            <div className="activity-row">
              <span className="activity-dot">
                <Activity size={13} />
              </span>
              <div>
                <p>
                  {data.state?.run_ref
                    ? "已读取保存的运行快照"
                    : "尚无活动运行引用"}
                </p>
                <div className="line-sub">
                  {data.state?.snapshot_stale
                    ? "保存的快照较旧，请查看诊断"
                    : "快照与进程存活分别显示"}
                </div>
              </div>
              <span className="time">
                {data.state?.status.updated
                  ? timeLabel(data.state.status.updated)
                  : "—"}
              </span>
            </div>
            <div className="activity-row">
              <span className="activity-dot">
                <FileCheck2 size={13} />
              </span>
              <div>
                <p>
                  {data.profile?.policy_valid
                    ? "本地策略已通过校验"
                    : "本地配置待检查"}
                </p>
                <div className="line-sub">
                  {data.profile?.transaction_pending
                    ? "存在未完成的配置事务"
                    : "界面仅查询现有配置"}
                </div>
              </div>
              <Badge>{data.profile?.policy_valid ? "已校验" : "待配置"}</Badge>
            </div>
            <div className="activity-row">
              <span className="activity-dot">
                <Network size={13} />
              </span>
              <div>
                <p>
                  {data.nodes
                    ? `${data.nodes.total} 个节点在本地库存`
                    : "节点库存尚未读取"}
                </p>
                <div className="line-sub">同步后的库存在下次启动生效</div>
              </div>
              <button
                className="link-btn"
                onClick={() => go("nodes")}
                aria-label="查看节点库存"
              >
                <ArrowRight size={13} />
              </button>
            </div>
          </div>
        </section>
      </div>
      <div className="hint">
        <strong>桌面首包已接入只读状态。</strong>{" "}
        连接、认证和配置写入将在取消与恢复通路完成后开放。已有 CLI
        运行继续由独立的网络引擎管理。
      </div>
    </>
  );
}

function NodePage({
  data,
  loading,
  loadNodes,
}: {
  data: Data;
  loading: boolean;
  loadNodes: (offset: number) => Promise<void>;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const nodes = data.nodes;
  const items = (nodes?.items ?? []).filter(
    (n) =>
      (filter === "all" || n.type.toLowerCase() === filter) &&
      `${n.name} ${n.type}`.toLowerCase().includes(query.toLowerCase()),
  );
  return (
    <>
      <Header
        eyebrow="PERSONAL NETWORK"
        title="让合适的节点，自动上场。"
        description="查看下次启动的本地库存；当前运行仍使用启动时的节点集。"
      >
        <RefreshButton
          loading={loading}
          onClick={() => {
            void loadNodes(nodes?.offset ?? 0);
          }}
        />
      </Header>
      <div className="notice">
        <Sparkles size={21} strokeWidth={1.5} />
        <div>
          <strong>由运行引擎自动选择</strong>
          <p>暂不提供探测延迟和选点原因，也不将库存编号与当前运行直接对应。</p>
        </div>
        <Badge>下次启动库存</Badge>
      </div>
      <div className="toolbar">
        <div className="segmented" aria-label="节点筛选">
          <button
            className={filter === "all" ? "active" : ""}
            onClick={() => setFilter("all")}
            aria-pressed={filter === "all"}
          >
            全部节点 {nodes?.total ?? 0}
          </button>
          <button
            className={filter === "vless" ? "active" : ""}
            onClick={() => setFilter("vless")}
            aria-pressed={filter === "vless"}
          >
            VLESS
          </button>
          <button
            className={filter === "hysteria2" ? "active" : ""}
            onClick={() => setFilter("hysteria2")}
            aria-pressed={filter === "hysteria2"}
          >
            Hysteria2
          </button>
        </div>
        <label className="search">
          <Search size={14} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜索节点名称或协议"
            aria-label="搜索当前页节点"
          />
        </label>
      </div>
      <section className="panel">
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>节点</th>
                <th>协议</th>
                <th>库存状态</th>
              </tr>
            </thead>
            <tbody>
              {items.map((node) => (
                <tr key={node.id}>
                  <td>
                    <div className="node-name">
                      <span className="node-letter">
                        <Network size={14} strokeWidth={1.3} />
                      </span>
                      <div>
                        <div className="node-title">{node.name}</div>
                        <div className="node-sub">本地库存 · 个人节点池</div>
                      </div>
                    </div>
                  </td>
                  <td>
                    <Badge>{node.type.toUpperCase()}</Badge>
                  </td>
                  <td>
                    <Badge>库存节点</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!items.length && (
          <Empty
            title={nodes?.total ? "没有匹配的节点" : "节点库存尚不可用"}
            text={
              nodes?.total
                ? "试试其他名称，或查看全部库存。"
                : "使用已有 CLI 导入节点或同步订阅后，再刷新本页。"
            }
          />
        )}
        <div className="table-note">
          <Info size={13} />
          运行保存的选择：{data.state?.status.personal || "尚未选择"} ·
          尚未与本地库存核对。节点地址与凭据不会送入界面。
        </div>
        {nodes && nodes.total > nodes.limit && (
          <div className="pagination">
            <span>
              {nodes.offset + 1}–
              {Math.min(nodes.offset + nodes.items.length, nodes.total)} /{" "}
              {nodes.total} · 搜索仅作用于当前页
            </span>
            <div className="actions">
              <button
                className="btn small"
                disabled={loading || nodes.offset === 0}
                onClick={() => {
                  void loadNodes(nodes.offset - nodes.limit);
                }}
                aria-label="上一页"
              >
                <ChevronLeft size={13} />
              </button>
              <button
                className="btn small"
                disabled={
                  loading || nodes.offset + nodes.items.length >= nodes.total
                }
                onClick={() => {
                  void loadNodes(nodes.offset + nodes.limit);
                }}
                aria-label="下一页"
              >
                <ChevronRight size={13} />
              </button>
            </div>
          </div>
        )}
      </section>
      <div className="info-strip">
        <div className="info-cell">
          <b>稳定优先</b>
          <p>运行引擎保持健康节点，满足切换条件后才更换出口。</p>
        </div>
        <div className="info-cell">
          <b>分别验证</b>
          <p>节点候选、代理入口与系统路径需要各自的检查证据。</p>
        </div>
        <div className="info-cell">
          <b>配置与运行分开</b>
          <p>本地库存可能已更新；既有运行仍使用启动时的节点集。</p>
        </div>
      </div>
    </>
  );
}

function RulesPage({
  data,
  loading,
  loadRules,
}: {
  data: Data;
  loading: boolean;
  loadRules: (offset: number) => Promise<void>;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const rules = (data.config?.rules ?? []).filter(
    (rule) =>
      (filter === "all" || rule.target === filter) &&
      `${rule.value} ${sourceNames[rule.source] ?? rule.source}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  return (
    <>
      <Header
        eyebrow="TRAFFIC RULES"
        title="每个目的地，都有自己的路。"
        description="查看真实规则与来源，配置变更默认在下次启动生效。"
      >
        <RefreshButton
          loading={loading}
          onClick={() => {
            void loadRules(data.config?.offset ?? 0);
          }}
        />
      </Header>
      <div className="toolbar">
        <div className="segmented" aria-label="规则筛选">
          {[
            ["all", "全部规则"],
            ["company", "公司"],
            ["personal", "个人"],
            ["direct", "直连"],
          ].map(([id, label]) => (
            <button
              key={id}
              className={filter === id ? "active" : ""}
              onClick={() => setFilter(id)}
              aria-pressed={filter === id}
            >
              {label}
            </button>
          ))}
        </div>
        <label className="search">
          <Search size={14} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜索本页域名或规则来源"
            aria-label="搜索当前页规则"
          />
        </label>
      </div>
      <div className="rule-layout">
        <section className="panel">
          <PanelHead
            after={<span className="small-note">静态配置 · 只读</span>}
          >
            当前规则<Badge>{data.config?.total ?? 0} 条</Badge>
          </PanelHead>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>目标 / 匹配方式</th>
                  <th>出口</th>
                  <th>来源</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule, i) => (
                  <tr key={`${rule.source}-${rule.index}-${i}`}>
                    <td>
                      <div className="mono">{rule.value || "其余目标"}</div>
                      <div className="node-sub">
                        {(
                          {
                            DOMAIN: "精确域名",
                            "DOMAIN-SUFFIX": "域名后缀",
                            "IP-CIDR": "IPv4 网段",
                            MATCH: "默认匹配",
                          } as Record<string, string>
                        )[rule.type] ?? rule.type}
                        {rule.guard ? " · 保护规则" : ""}
                      </div>
                    </td>
                    <td>
                      <Badge
                        tone={
                          rule.target === "company" && !rule.guard
                            ? "green"
                            : ""
                        }
                      >
                        {channelNames[rule.target] ?? "未知出口"}
                      </Badge>
                    </td>
                    <td>
                      <span className="small-note">
                        {sourceNames[rule.source] ??
                          (rule.source.startsWith("subscription")
                            ? "订阅规则"
                            : rule.source)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!rules.length && (
            <Empty
              title={
                data.profile?.configured ? "没有匹配的规则" : "等待本地规则配置"
              }
              text={
                data.profile?.configured
                  ? "调整筛选条件后再试。"
                  : "选择已有的本地配置后，即可查看分流计划。"
              }
            />
          )}
          <div className="table-note">
            <Wifi size={13} />
            未命中的目标默认走本机直连；规则查询不证明实际连通性。
          </div>
          {data.config && data.config.total > data.config.limit && (
            <div className="pagination">
              <span>
                {data.config.offset + 1}–
                {Math.min(
                  data.config.offset + data.config.rules.length,
                  data.config.total,
                )}{" "}
                / {data.config.total} · 搜索仅作用于当前页
              </span>
              <div className="actions">
                <button
                  className="btn small"
                  disabled={loading || data.config.offset === 0}
                  onClick={() => {
                    void loadRules(data.config!.offset - data.config!.limit);
                  }}
                  aria-label="上一页规则"
                >
                  <ChevronLeft size={13} />
                </button>
                <button
                  className="btn small"
                  disabled={
                    loading ||
                    data.config.offset + data.config.rules.length >=
                      data.config.total
                  }
                  onClick={() => {
                    void loadRules(data.config!.offset + data.config!.limit);
                  }}
                  aria-label="下一页规则"
                >
                  <ChevronRight size={13} />
                </button>
              </div>
            </div>
          )}
        </section>
        <aside className="rule-sidebar">
          <section className="panel">
            <PanelHead>规则优先级</PanelHead>
            <div className="order-list">
              {[
                "公司固定目标",
                "个人固定目标",
                "本地覆盖规则",
                "订阅规则",
                "其余直连",
              ].map((label, i) => (
                <div className="order-item" key={label}>
                  <b>{i + 1}</b>
                  {label}
                </div>
              ))}
            </div>
          </section>
          <section className="panel recovery-panel" style={{ marginTop: 0 }}>
            <h3>明确授权，各自生效。</h3>
            <p>
              订阅不会增加公司授权，也不会覆盖前面的固定目标。桌面编辑、预览和回退将在配置事务接入后开放。
            </p>
            <Badge>本地配置</Badge>
          </section>
        </aside>
      </div>
      <div className="hint">
        <strong>规则可能包含内部地址，请仅在本机查看。</strong> 当前界面通过 Go
        查询有序分流计划，配置和规则内容不会进入诊断摘要。
      </div>
    </>
  );
}

function Diagnostics({
  data,
  now,
  loading,
  refresh,
  environment,
  checking,
  checkEnvironment,
  showRecovery,
}: {
  data: Data;
  now: number;
  loading: boolean;
  refresh: () => void;
  environment: Environment | null;
  checking: boolean;
  checkEnvironment: () => void;
  showRecovery: () => void;
}) {
  const channels = currentChannels(data.state, now);
  const recoverySupported = data.hello?.capabilities.native_lifecycle;
  return (
    <>
      <Header
        eyebrow="STATUS & RECOVERY"
        title="看清状态，安心恢复。"
        description="分别查看通道证据、控制接口与恢复需求。"
      >
        <RefreshButton loading={loading} onClick={refresh}>
          刷新状态
        </RefreshButton>
      </Header>
      <section className="diagnostic-summary">
        <span className="check-circle">
          <ShieldCheck size={22} strokeWidth={1.5} />
        </span>
        <div>
          <h2>
            {data.state?.recovery_required
              ? "存在尚未确认的运行，请保留恢复资料"
              : data.state?.run_ref
                ? "已读取保存的运行状态"
                : "尚无活动运行引用"}
          </h2>
          <p>状态快照不等于实时进程存活证明，过期证据会自动显示为待确认。</p>
        </div>
        <Badge tone={data.state?.snapshot_stale ? "warning" : ""}>
          {data.state?.snapshot_stale ? "快照较旧" : "保存的状态"}
        </Badge>
      </section>
      <div className="diagnostic-grid">
        <div>
          <section className="panel">
            <PanelHead after={<Badge>独立证据</Badge>}>通道检查</PanelHead>
            <div className="check-list">
              {(["company", "personal", "direct"] as ChannelName[]).map(
                (name) => {
                  const channel = channels[name],
                    Icon =
                      name === "company"
                        ? ShieldCheck
                        : name === "personal"
                          ? Globe2
                          : Wifi;
                  return (
                    <div className="check-row" key={name}>
                      <Icon size={18} strokeWidth={1.5} />
                      <div className="check-label">
                        {channelNames[name]}
                        <small>
                          {pathLabel(channel.path_state)} ·{" "}
                          {serviceLabel(channel.service_state)}
                          <br />
                          最后检查：{timeLabel(channel.checked_at)} ·{" "}
                          {elapsedLabel(channel.checked_at, now)}
                        </small>
                      </div>
                      <Badge
                        tone={
                          channel.state === "ready"
                            ? "green"
                            : channel.state === "unavailable"
                              ? "danger"
                              : ""
                        }
                      >
                        {stateLabel(channel)}
                      </Badge>
                    </div>
                  );
                },
              )}
            </div>
            <div className="table-note">
              <Info size={13} />
              运行存活：尚未检查 · 界面状态约每 2 秒读取一次。
            </div>
          </section>
          <section className="panel" style={{ marginTop: 17 }}>
            <PanelHead
              after={
                environment ? (
                  <button
                    className="link-btn"
                    disabled={checking}
                    onClick={checkEnvironment}
                  >
                    <RefreshCw size={12} className={checking ? "spin" : ""} />
                    {checking ? "检查中" : "重新检查"}
                  </button>
                ) : undefined
              }
            >
              本机环境
            </PanelHead>
            {environment ? (
              <div className="check-list">
                {environment.checks.map((check) => (
                  <div className="check-row" key={check.id}>
                    <span
                      className={`dot ${check.state === "passed" ? "" : check.state === "failed" ? "danger" : "warning"}`}
                    />
                    <div className="check-label">
                      {check.label}
                      <small>{check.message}</small>
                    </div>
                    <Badge
                      tone={
                        check.state === "passed"
                          ? "green"
                          : check.state === "failed"
                            ? "danger"
                            : "warning"
                      }
                    >
                      {(
                        {
                          passed: "通过",
                          failed: "未通过",
                          warning: "需关注",
                          not_checked: "未检查",
                        } as Record<string, string>
                      )[check.state] ?? "待确认"}
                    </Badge>
                  </div>
                ))}
              </div>
            ) : (
              <Empty
                title="尚未运行环境检查"
                text="检查组件与配置能力，读取过程不请求管理员权限。"
              >
                <button
                  className="btn"
                  disabled={checking}
                  onClick={checkEnvironment}
                >
                  <FileCheck2 size={13} />
                  {checking ? "正在检查" : "检查本机环境"}
                </button>
              </Empty>
            )}
            <div className="table-note">
              <Info size={13} />
              {environment
                ? `检查于 ${timeLabel(environment.checked_at)} · `
                : ""}
              环境检查不代表已连接，也不开放连接操作。
            </div>
          </section>
        </div>
        <div>
          <section className="panel">
            <PanelHead>版本与运行信息</PanelHead>
            <div className="system-list">
              {[
                ["应用版本", data.hello?.build.version ?? "等待后端"],
                [
                  "构建平台",
                  data.hello
                    ? `${platformNames[data.hello.build.os] ?? data.hello.build.os} / ${data.hello.build.arch}`
                    : "尚未读取",
                ],
                [
                  "构建模式",
                  data.hello
                    ? (modeNames[data.hello.mode] ?? data.hello.mode)
                    : "尚未读取",
                ],
                ["运行引用", data.state?.run_ref ?? "无"],
                ["状态更新时间", timeLabel(data.state?.status.updated)],
                [
                  "恢复标记",
                  data.state?.stop_requested ? "已请求停止" : "未请求停止",
                ],
              ].map(([label, value]) => (
                <div className="system-item" key={label}>
                  <span>{label}</span>
                  <strong>{value}</strong>
                </div>
              ))}
            </div>
          </section>
          <section className="panel recovery-panel">
            <h3>需要恢复原网络？</h3>
            {recoverySupported === false ? (
              <p>
                此 Windows 只读预览不提供恢复，请使用创建该运行的 CLI
                及其独立恢复入口。
              </p>
            ) : recoverySupported === true ? (
              <>
                <p>
                  使用应用之外的「停止与恢复」入口，由已有 Go
                  引擎确认并恢复本次管理的网络设置。恢复尚未确认时请保留运行目录。
                </p>
                {data.recovery?.instructions.map((line, i) => (
                  <p key={i}>{line}</p>
                ))}
                <button className="btn" onClick={showRecovery}>
                  <FolderOpen size={13} />
                  找到独立恢复入口
                </button>
                <p
                  className="small-note"
                  style={{ marginTop: 12, marginBottom: 0 }}
                >
                  此按钮打开入口所在目录；实际恢复由你显式运行。
                </p>
              </>
            ) : (
              <p>正在确认本机恢复能力。</p>
            )}
          </section>
        </div>
      </div>
    </>
  );
}

function Preferences({
  data,
  loading,
  chooseProfile,
}: {
  data: Data;
  loading: boolean;
  chooseProfile: () => void;
}) {
  return (
    <>
      <Header
        eyebrow="LOCAL WORKSPACE"
        title="一个安静的本地工作空间。"
        description="沿用既有 CLI 配置，桌面应用只保存工作空间偏好。"
      />
      <div className="preferences-grid">
        <section className="panel">
          <PanelHead icon={FolderOpen}>本地配置</PanelHead>
          <div className="profile-block">
            <p>
              {data.profile?.configured
                ? `当前使用「${data.profile.profile_name}」。配置、节点凭据与公司认证仍由本地 Go 后端管理。`
                : "可以选择已经由 CLI 初始化的配置目录。首次导入和订阅同步将在下一阶段接入桌面。"}
            </p>
            <button className="btn" disabled={loading} onClick={chooseProfile}>
              <FolderOpen size={14} />
              选择已有配置目录
            </button>
            <div className="setting-row">
              <div>
                策略校验<small>本地配置的安全投影</small>
              </div>
              <Badge tone={data.profile?.policy_valid ? "green" : ""}>
                {data.profile?.policy_valid ? "已通过" : "待检查"}
              </Badge>
            </div>
            <div className="setting-row">
              <div>
                节点库存<small>缓存与当前运行分别管理</small>
              </div>
              <Badge>{data.profile?.node_count ?? 0} 个节点</Badge>
            </div>
            <div className="setting-row">
              <div>
                配置事务<small>未完成事务需要通过原入口处理</small>
              </div>
              <Badge tone={data.profile?.transaction_pending ? "warning" : ""}>
                {data.profile?.transaction_pending ? "未完成" : "无待处理事务"}
              </Badge>
            </div>
          </div>
        </section>
        <section className="panel">
          <PanelHead icon={Settings2}>界面与应用</PanelHead>
          <div className="profile-block">
            <div className="setting-row">
              <div>
                Jade Workspace<small>方案一 · 雾白工作台</small>
              </div>
              <span className="theme-swatch" aria-label="雾白与玉绿色主题" />
            </div>
            <div className="setting-row">
              <div>
                状态读取<small>界面自行老化过期证据</small>
              </div>
              <Badge>每 2 秒</Badge>
            </div>
            <div className="setting-row">
              <div>
                桌面阶段<small>普通权限 Go bridge</small>
              </div>
              <Badge>只读预览</Badge>
            </div>
            <div className="setting-row">
              <div>
                应用版本<small>手动更新</small>
              </div>
              <Badge>{data.hello?.build.version ?? "工程预览"}</Badge>
            </div>
          </div>
        </section>
      </div>
      <div className="hint">
        <strong>真实配置留在本机。</strong> 前端不保存节点地址、密钥、订阅链接或
        VPN 会话。选择配置目录仅切换查询对象。
      </div>
    </>
  );
}

export default function App() {
  const app = useData();
  const clientMode = app.data.hello?.capabilities.windows_client === true && !!window.lumina?.client;
  const [page, setPage] = useState<Page>("overview");
  const [now, setNow] = useState(Date.now());
  const [environment, setEnvironment] = useState<Environment | null>(null);
  const [checking, setChecking] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const environmentChecks = useRef(new EnvironmentChecks());
  const heading = useRef<HTMLElement>(null);
  const pages: [Page, string, React.ElementType, string][] = [
    ["overview", "总览", LayoutGrid, "01"],
    ["nodes", "代理节点", Network, "02"],
    ["rules", "分流规则", Route, "03"],
    ["diagnostics", "诊断与恢复", Activity, "04"],
  ];
  const pageName =
    page === "settings"
      ? "工作空间设置"
      : pages.find((p) => p[0] === page)?.[1];
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const go = (next: Page) => {
    setPage(next);
    setNotice(null);
    window.setTimeout(() => heading.current?.focus(), 0);
  };
  const refresh = () => {
    void app.refresh(true);
  };
  const chooseProfile = async (restoreDefault = false) => {
    if (!environmentChecks.current.beginProfileSelection()) return;
    setEnvironment(null);
    setChecking(false);
    setNotice(null);
    try {
      await app.chooseProfile(restoreDefault);
    } finally {
      environmentChecks.current.endProfileSelection();
      setEnvironment(null);
      setChecking(false);
    }
  };
  const checkEnvironment = () =>
    environmentChecks.current.run(() => window.lumina.checkEnvironment(), {
      started: () => {
        setChecking(true);
        setNotice(null);
      },
      succeeded: setEnvironment,
      failed: (error) => setNotice(errorMessage(error)),
      finished: () => setChecking(false),
    });
  const showRecovery = async () => {
    try {
      if (!(await window.lumina.showRecovery()))
        setNotice(
          "独立恢复入口暂不可用，请使用已有 CLI 的「停止与恢复」入口。",
        );
    } catch {
      setNotice("独立恢复入口暂不可用，请使用已有 CLI 的「停止与恢复」入口。");
    }
  };
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="logo">
          <svg
            className="logo-mark"
            viewBox="0 0 36 40"
            fill="none"
            aria-hidden="true"
          >
            <path
              d="M18 3 3 31h30L18 3Z"
              stroke="currentColor"
              strokeWidth="1.4"
            />
            <path
              d="m18 14-7 13h14l-7-13Z"
              stroke="currentColor"
              strokeWidth="1.4"
            />
            <path
              d="M18 21v15M8 37h20"
              stroke="currentColor"
              strokeWidth="1.3"
            />
          </svg>
          <div className="logo-name">
            Lumina
            <span className="logo-caption">
              LOCAL
              <br />
              NETWORK
            </span>
          </div>
        </div>
        <div className="nav-label">工作空间</div>
        <nav className="nav" aria-label="工作空间导航">
          {pages.map(([id, label, Icon, number]) => (
            <button
              key={id}
              className={page === id ? "active" : ""}
              aria-current={page === id ? "page" : undefined}
              onClick={() => go(id)}
            >
              <Icon size={17} strokeWidth={1.45} />
              <span>{label}</span>
              <span className="nav-number">{number}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <button
            className="settings-link"
            onClick={() => go("settings")}
            aria-current={page === "settings" ? "page" : undefined}
          >
            <Settings2 size={15} strokeWidth={1.4} />
            工作空间设置
          </button>
          <Badge>{clientMode ? "Windows 客户端" : "只读工程预览"}</Badge>
          <div className="build">
            <i className={`dot ${app.control === "available" ? "" : "dim"}`} />
            {app.data.hello?.build.version ?? "LuminaVPN Desktop"}
          </div>
        </div>
      </aside>
      <main className="main" ref={heading} tabIndex={-1} aria-label={pageName}>
        <div className="topline">
          <div className="crumb">
            工作空间<span>/</span>
            <strong>{pageName}</strong>
          </div>
          <div className="top-right">
            <span>
              {app.data.hello
                ? (modeNames[app.data.hello.mode] ??
                  `${platformNames[app.data.hello.build.os] ?? app.data.hello.build.os} · ${app.data.hello.build.arch}`)
                : "本机工作空间"}
            </span>
            <Badge tone={app.control === "available" ? "green" : ""} dot>
              {app.control === "available"
                ? "控制接口可用"
                : app.control === "connecting"
                  ? "正在读取"
                  : "控制接口断开"}
            </Badge>
          </div>
        </div>
        <div className="page" key={clientMode ? "client-workspace" : page}>
          {(app.error || notice) && (
            <div className="control-banner" role="status">
              <Unplug size={15} />
              <span>{notice ?? app.error}</span>
              {notice ? (
                <button
                  className="link-btn"
                  onClick={() => setNotice(null)}
                  aria-label="关闭提示"
                >
                  <X size={14} />
                </button>
              ) : (
                <button
                  className="link-btn"
                  disabled={app.loading}
                  onClick={refresh}
                >
                  重试
                  <RefreshCw size={12} />
                </button>
              )}
            </div>
          )}
          {clientMode && window.lumina.client && app.data.profile?.profile_id && <ClientWorkspace key={app.data.profile.profile_id} profileID={app.data.profile.profile_id} page={page} validationOnly={app.data.hello?.capabilities.validation_only===true} api={window.lumina.client} refreshInventory={refresh} nodes={app.data.nodes} subscriptions={app.data.subscriptions} config={app.data.config} loadNodes={app.loadNodes} loadRules={app.loadRules} chooseProfile={()=>chooseProfile()} restoreDefaultProfile={()=>chooseProfile(true)} checking={checking} environmentCheck={environment} checkEnvironment={() => { void checkEnvironment() }} showRecovery={() => { void showRecovery() }} />}
          {!clientMode && page === "overview" && (
            <Overview
              data={app.data}
              now={now}
              control={app.control}
              go={go}
              loading={app.loading}
              refresh={refresh}
            />
          )}
          {!clientMode && page === "nodes" && (
            <NodePage
              data={app.data}
              loading={app.loading}
              loadNodes={app.loadNodes}
            />
          )}
          {!clientMode && page === "rules" && (
            <RulesPage
              data={app.data}
              loading={app.loading}
              loadRules={app.loadRules}
            />
          )}
          {!clientMode && page === "diagnostics" && (
            <Diagnostics
              data={app.data}
              now={now}
              loading={app.loading}
              refresh={refresh}
              environment={environment}
              checking={checking}
              checkEnvironment={() => {
                void checkEnvironment();
              }}
              showRecovery={() => {
                void showRecovery();
              }}
            />
          )}
          {!clientMode && page === "settings" && (
            <Preferences
              data={app.data}
              loading={app.loading}
              chooseProfile={chooseProfile}
            />
          )}
          <footer className="footerline">
            <span>
              <i
                className={`dot ${app.control === "available" ? "" : "dim"}`}
              />
              {app.control === "available"
                ? "控制接口可用 · 网络证据分别显示"
                : "控制接口未连接 · 保留最近的状态"}
            </span>
            <span>配置保存在本机 · Jade Workspace</span>
          </footer>
        </div>
      </main>
      <div className="sr-only" role="status" aria-live="polite">
        {app.control === "available"
          ? "控制接口已连接"
          : app.control === "unavailable"
            ? "控制接口已断开"
            : "正在读取本地状态"}
      </div>
    </div>
  );
}
