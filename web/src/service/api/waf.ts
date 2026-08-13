import { request } from '../request';

/** 仪表盘聚合统计 */
export function fetchDashboardStats(days = 14) {
  return request<Api.Waf.DashboardStats>({ url: '/dashboard/stats', params: { days } });
}

/** 攻击事件列表 */
export function fetchEvents(params: Record<string, string | number>) {
  return request<Api.Waf.PageResult<Api.Waf.EventItem>>({ url: '/events', params });
}

/** 攻击事件详情（含命中规则/请求头/请求体） */
export function fetchEventDetail(id: number | string) {
  return request<Api.Waf.EventItem>({ url: `/events/${id}` });
}

/** 消费 Redis 事件队列 */
export function consumeEvents() {
  return request<{ status: string; consumed: number }>({ url: '/events/consume', method: 'post' });
}

/** 流量记录列表 */
export function fetchTraffic(params: Record<string, string | number>) {
  return request<Api.Waf.PageResult<Api.Waf.TrafficItem>>({ url: '/traffic', params });
}

/** 流量统计 */
export function fetchTrafficStats() {
  return request<{ total: number; attack: number }>({ url: '/traffic/stats' });
}

/** 流量趋势 */
export function fetchTrafficTrend(days = 14) {
  return request<{ days: number; items: { date: string; total: number; attack: number }[] }>({
    url: '/traffic/trend',
    params: { days }
  });
}

/** 消费流量队列 */
export function consumeTraffic() {
  return request<{ status: string; consumed: number }>({ url: '/traffic/consume', method: 'post' });
}

/** 清理过期流量 */
export function cleanupTraffic(days: number) {
  return request<{ status: string; deleted: number }>({ url: '/traffic/cleanup', method: 'post', params: { days } });
}

/** 规则列表 */
export function fetchRules(params: Record<string, string | number> = {}) {
  return request<Api.Waf.Rule[]>({ url: '/rules', params });
}

/** 新建规则 */
export function createRule(data: Partial<Api.Waf.Rule>) {
  return request<Api.Waf.Rule>({ url: '/rules', method: 'post', data });
}

/** 更新规则 */
export function updateRule(id: number, data: Partial<Api.Waf.Rule>) {
  return request<Api.Waf.Rule>({ url: `/rules/${id}`, method: 'put', data });
}

/** 删除规则 */
export function deleteRule(id: number) {
  return request<{ status: string }>({ url: `/rules/${id}`, method: 'delete' });
}

/** 启用/禁用规则 */
export function setRuleEnabled(id: number, enabled: boolean) {
  return request<{ status: string }>({ url: `/rules/${id}/enabled`, method: 'patch', data: { enabled } });
}

/** 发布规则到引擎 */
export function publishRules() {
  return request<{ status: string }>({ url: '/rules/publish', method: 'post' });
}

/** 规则测试 */
export function testRule(data: Api.Waf.RuleTestReq) {
  return request<{ matched: boolean; note?: string }>({ url: '/rules/test', method: 'post', data });
}

/** CC 规则列表 */
export function fetchCcRules() {
  return request<Api.Waf.CcRule[]>({ url: '/cc-rules' });
}

/** 新建 CC 规则 */
export function createCcRule(data: Partial<Api.Waf.CcRule>) {
  return request<Api.Waf.CcRule>({ url: '/cc-rules', method: 'post', data });
}

/** 更新 CC 规则 */
export function updateCcRule(id: number, data: Partial<Api.Waf.CcRule>) {
  return request<Api.Waf.CcRule>({ url: `/cc-rules/${id}`, method: 'put', data });
}

/** 删除 CC 规则 */
export function deleteCcRule(id: number) {
  return request<{ status: string }>({ url: `/cc-rules/${id}`, method: 'delete' });
}

/** 启用/禁用 CC 规则 */
export function setCcRuleEnabled(id: number, enabled: boolean) {
  return request<{ status: string }>({ url: `/cc-rules/${id}/enabled`, method: 'patch', data: { enabled } });
}

/** 发布 CC 规则 */
export function publishCcRules() {
  return request<{ status: string }>({ url: '/cc-rules/publish', method: 'post' });
}

/** IP 列表订阅 */
export function fetchIpListSubs() {
  return request<Api.Waf.IpListSub[]>({ url: '/ip-list-subs' });
}

/** 新建 IP 列表订阅 */
export function createIpListSub(data: Partial<Api.Waf.IpListSub>) {
  return request<Api.Waf.IpListSub>({ url: '/ip-list-subs', method: 'post', data });
}

/** 更新 IP 列表订阅 */
export function updateIpListSub(id: number, data: Partial<Api.Waf.IpListSub>) {
  return request<Api.Waf.IpListSub>({ url: `/ip-list-subs/${id}`, method: 'put', data });
}

/** 删除 IP 列表订阅 */
export function deleteIpListSub(id: number) {
  return request<{ status: string }>({ url: `/ip-list-subs/${id}`, method: 'delete' });
}

/** 启用/禁用 IP 列表订阅 */
export function setIpListSubEnabled(id: number, enabled: boolean) {
  return request<{ status: string }>({ url: `/ip-list-subs/${id}/enabled`, method: 'patch', data: { enabled } });
}

/** 同步 IP 列表 */
export function syncIpListSub(id: number) {
  return request<{ status: string; count?: number }>({ url: `/ip-list-subs/${id}/sync`, method: 'post' });
}

/** 读取系统配置 */
export function fetchConfig() {
  return request<{ config: Record<string, unknown> }>({ url: '/config' });
}

/** 保存系统配置 */
export function saveConfig(config: Record<string, unknown>) {
  return request<{ status: string }>({ url: '/config', method: 'put', data: { config } });
}

/** 获取接入指引（一键安装命令 / 组件下载 / nginx 配置） */
export function fetchSetupGuide() {
  return request<{
    redis: { addr: string; password: string; db: number };
    install_command: string;
    download_url: string;
    nginx_config: string;
  }>({ url: '/setup/guide' });
}

/** 人机验证事件列表 */
export function fetchChallenges(params: Record<string, string | number>) {
  return request<Api.Waf.PageResult<Api.Waf.ChallengeItem>>({ url: '/challenges', params });
}

/** 消费人机验证队列 */
export function consumeChallenges() {
  return request<{ status: string; consumed: number }>({ url: '/challenges/consume', method: 'post' });
}
