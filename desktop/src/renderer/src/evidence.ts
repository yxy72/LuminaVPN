import type { Channel, ChannelName, State } from "../../../protocol/types";

export const EVIDENCE_TTL_MS = 90_000;

export function ageChannel(channel: Channel | undefined, now: number): Channel {
  if (!channel)
    return {
      state: "unknown",
      reason: "not_checked",
      checked_at: null,
      path_state: "unknown",
      service_state: "not_checked",
    };
  const checked = channel.checked_at ? Date.parse(channel.checked_at) : NaN;
  if (
    !Number.isFinite(checked) ||
    checked > now ||
    now - checked > EVIDENCE_TTL_MS
  ) {
    return {
      ...channel,
      state: channel.state === "ready" ? "unknown" : channel.state,
      reason: channel.state === "ready" ? "check_expired" : channel.reason,
      path_state: "unknown",
      service_state: "unknown",
    };
  }
  return channel;
}

export function currentChannels(
  state: State | null,
  now: number,
): Record<ChannelName, Channel> {
  return {
    company: ageChannel(state?.status.channels.company, now),
    personal: ageChannel(state?.status.channels.personal, now),
    direct: ageChannel(state?.status.channels.direct, now),
  };
}

export function timeLabel(value: string | null | undefined): string {
  if (!value || !Number.isFinite(Date.parse(value))) return "尚未检查";
  return new Date(value).toLocaleTimeString("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function elapsedLabel(
  value: string | null | undefined,
  now: number,
): string {
  const parsed = value ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed) || parsed > now) return "尚未检查";
  const seconds = Math.floor((now - parsed) / 1000);
  if (seconds < 60) return `${seconds} 秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
  return `${Math.floor(seconds / 86400)} 天前`;
}
