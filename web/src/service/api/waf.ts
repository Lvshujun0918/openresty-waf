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

/** 规则发布历史 */
export function fetchPublishHistory() {
  return request<Api.Waf.PublishHistory[]>({ url: '/rules/publish-history' });
}

/** 回滚到指定发布历史快照 */
export function rollbackRules(id: number) {
  return request<{ status: string }>({ url: `/rules/rollback/${id}`, method: 'post' });
}

/** 灰度发布状态 */
export function fetchCanaryStatus() {
  return request<Api.Waf.CanaryStatus>({ url: '/rules/canary/status' });
}

/** 发起灰度发布（按百分比/IP 名单下发新规则集） */
export function publishCanary(percent: number, ips: string[]) {
  return request<{ status: string; version: string; rule_count: number; percent: number; ips: string[] }>({
    url: '/rules/publish/canary',
    method: 'post',
    data: { percent, ips }
  });
}

/** 灰度转全量（晋升后清除灰度键） */
export function promoteCanary() {
  return request<{ status: string }>({ url: '/rules/publish/promote', method: 'post' });
}

/** 终止灰度，全部流量回退稳定规则集 */
export function abortCanary() {
  return request<{ status: string }>({ url: '/rules/publish/canary', method: 'delete' });
}

/** 导出全部规则（返回 JSON 数组，前端生成文件下载） */
export function exportRules() {
  return request<Api.Waf.Rule[]>({ url: '/rules/export' });
}

/** 导入规则（JSON 数组） */
export function importRules(rules: unknown[]) {
  return request<{ imported: number; skipped: number }>({ url: '/rules/import', method: 'post', data: { rules } });
}

/** 当前生效封禁列表 */
export function fetchBans() {
  return request<Api.Waf.BanEntry[]>({ url: '/bans' });
}

/** 解除封禁 */
export function unbanIP(ip: string) {
  return request<{ status: string }>({ url: '/bans', method: 'delete', params: { ip } });
}

/** 一键封禁事件来源 IP（hours<=0 永久） */
export function banEvent(id: number, hours: number) {
  return request<{ status: string; ip: string }>({ url: `/events/${id}/ban`, method: 'post', data: { hours } });
}

/** 全规则重放检测（攻击重放：跑全部启用规则返回命中列表） */
export function replayRequest(req: {
  method: string;
  uri: string;
  body?: string;
  content_type?: string;
  headers?: Record<string, string>;
  cookies?: string;
}) {
  return request<{ hits: { rule_id: string; name: string; group: string; msg: string; severity: number }[]; count: number }>({
    url: '/rules/test-all',
    method: 'post',
    data: req
  });
}

/** 规则测试 */
export function testRule(data: Api.Waf.RuleTestReq) {
  return request<{ matched: boolean; note?: string }>({ url: '/rules/test', method: 'post', data });
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

/** 版本健康信息（规则/配置/引擎版本） */
export function fetchConfigVersions() {
  return request<{ engine_version: string; rule_version: string; config_version: string }>({ url: '/config/versions' });
}

/** 获取接入指引（一键安装命令 / 组件下载 / nginx 配置） */
export function fetchSetupGuide() {
  return request<{
    redis: { addr: string; password: string; db: number };
    install_command: string;
    install_command_force: string;
    download_url: string;
    nginx_config: string;
  }>({ url: '/setup/guide' });
}

/** 测试并保存 Redis 配置 */
export function saveRedisConfig(data: { addr: string; password: string; db: number }) {
  return request<{ status: string }>({ url: '/setup/redis', method: 'post', data });
}

/** 人机验证事件列表 */
export function fetchChallenges(params: Record<string, string | number>) {
  return request<Api.Waf.PageResult<Api.Waf.ChallengeItem>>({ url: '/challenges', params });
}

/** 消费人机验证队列 */
export function consumeChallenges() {
  return request<{ status: string; consumed: number }>({ url: '/challenges/consume', method: 'post' });
}

/** CC 触发事件列表 */
export function fetchCcLogs(params: Record<string, string | number>) {
  return request<Api.Waf.PageResult<Api.Waf.CcLogItem>>({ url: '/cc-logs', params });
}

/** 消费 CC 触发队列 */
export function consumeCcLogs() {
  return request<{ status: string; consumed: number }>({ url: '/cc-logs/consume', method: 'post' });
}

/** 触发规则列表 */
export function fetchTriggerRules(params: Record<string, string | number> = {}) {
  return request<{ items: Api.Waf.TriggerRule[] }>({ url: '/trigger-rules', params });
}

/** 新建触发规则 */
export function createTriggerRule(data: Record<string, unknown>) {
  return request<Api.Waf.TriggerRule>({ url: '/trigger-rules', method: 'post', data });
}

/** 更新触发规则 */
export function updateTriggerRule(id: number, data: Record<string, unknown>) {
  return request<{ status: string }>({ url: `/trigger-rules/${id}`, method: 'put', data });
}

/** 删除触发规则 */
export function deleteTriggerRule(id: number) {
  return request<{ status: string }>({ url: `/trigger-rules/${id}`, method: 'delete' });
}

/** 启用/禁用触发规则 */
export function setTriggerRuleEnabled(id: number, enabled: boolean) {
  return request<{ status: string }>({ url: `/trigger-rules/${id}/enabled`, method: 'patch', data: { enabled } });
}

/** 发布触发规则到引擎 */
export function publishTriggerRules() {
  return request<{ status: string; version: string }>({ url: '/trigger-rules/publish', method: 'post' });
}

/** 引擎健康状态列表 */
export function fetchEngines() {
  return request<{ engines: Api.Waf.EngineStatus[]; count: number }>({ url: '/health/engines' });
}

/** 实时监控秒级曲线 */
export function fetchRealtime(minutes = 10) {
  return request<{ points: { ts: number; total: number; attack: number }[] }>({
    url: '/monitor/realtime',
    params: { minutes }
  });
}

/** 标记事件误报/取消误报 */
export function markFalsePositive(id: number, flag: boolean) {
  return request<{ status: string }>({ url: `/events/${id}/false-positive`, method: 'post', data: { flag } });
}

/** 事件一键豁免（生成 exempt 触发规则） */
export function exemptEvent(id: number) {
  return request<{ status: string; rule_id: number }>({ url: `/events/${id}/exempt`, method: 'post' });
}

/** 导出事件 CSV */
export function exportEventsCsv(params: Record<string, string | number>) {
  return request<Blob>({ url: '/events/export', params, responseType: 'blob' } as never);
}

/** 导出流量 CSV */
export function exportTrafficCsv(params: Record<string, string | number>) {
  return request<Blob>({ url: '/traffic/export', params, responseType: 'blob' } as never);
}

/** 规则命中统计排行 */
export function fetchRuleStats(group = '', limit = 20) {
  return request<{ items: { rule_id: string; hits: number; blocks: number; fps: number; fp_rate?: number }[] }>({
    url: '/rules/stats',
    params: { group, limit }
  });
}

/** 攻击类型趋势 */
export function fetchGroupTrend(group: string, days = 14) {
  return request<{ group: string; items: { date: string; attack: number }[] }>({
    url: '/dashboard/group-trend',
    params: { group, days }
  });
}

/** 攻击来源地区排行 */
export function fetchTopRegions(level = 'province', limit = 10) {
  return request<{ items: { region: string; count: number }[] }>({
    url: '/dashboard/top-regions',
    params: { level, limit }
  });
}

/** 告警通道列表 */
export function fetchAlertChannels() {
  return request<Api.Waf.AlertChannel[]>({ url: '/alerts/channels' });
}

/** 新建告警通道 */
export function createAlertChannel(data: Record<string, unknown>) {
  return request<{ ok: boolean; id: number }>({ url: '/alerts/channels', method: 'post', data });
}

/** 更新告警通道 */
export function updateAlertChannel(id: number, data: Record<string, unknown>) {
  return request<{ ok: boolean }>({ url: `/alerts/channels/${id}`, method: 'put', data });
}

/** 删除告警通道 */
export function deleteAlertChannel(id: number) {
  return request<{ ok: boolean }>({ url: `/alerts/channels/${id}`, method: 'delete' });
}

/** 测试告警通道 */
export function testAlertChannel(id: number) {
  return request<{ ok: boolean }>({ url: `/alerts/channels/${id}/test`, method: 'post' });
}

/** 告警规则列表 */
export function fetchAlertRules() {
  return request<Api.Waf.AlertRule[]>({ url: '/alerts/rules' });
}

/** 新建告警规则 */
export function createAlertRule(data: Record<string, unknown>) {
  return request<{ ok: boolean; id: number }>({ url: '/alerts/rules', method: 'post', data });
}

/** 更新告警规则 */
export function updateAlertRule(id: number, data: Record<string, unknown>) {
  return request<{ ok: boolean }>({ url: `/alerts/rules/${id}`, method: 'put', data });
}

/** 删除告警规则 */
export function deleteAlertRule(id: number) {
  return request<{ ok: boolean }>({ url: `/alerts/rules/${id}`, method: 'delete' });
}

/** 启用/禁用告警规则 */
export function setAlertRuleEnabled(id: number, enabled: boolean) {
  return request<{ ok: boolean }>({ url: `/alerts/rules/${id}/enabled`, method: 'patch', data: { enabled } });
}

/** 操作审计日志 */
export function fetchAuditLogs(params: Record<string, string | number>) {
  return request<Api.Waf.PageResult<Api.Waf.AuditLog>>({ url: '/audit-logs', params });
}

/** 登录会话列表 */
export function fetchSessions() {
  return request<{ sessions: Api.Waf.Session[] }>({ url: '/auth/sessions' });
}

/** 强制下线会话 */
export function kickSession(jti: string) {
  return request<{ ok: boolean }>({ url: `/auth/sessions/${jti}`, method: 'delete' });
}

/** 新增封禁（支持 IP+UA 维度） */
export function createBan(data: { ip: string; ua?: string; hours: number }) {
  return request<{ status: string }>({ url: '/bans', method: 'post', data });
}

/** 恶意指纹库列表 */
export function fetchBotFingerprints() {
  return request<Api.Waf.BotFingerprint[]>({ url: '/bots/fingerprints' });
}

/** 新建恶意指纹 */
export function createBotFingerprint(data: Record<string, unknown>) {
  return request<{ ok: boolean; id: number }>({ url: '/bots/fingerprints', method: 'post', data });
}

/** 更新恶意指纹 */
export function updateBotFingerprint(id: number, data: Record<string, unknown>) {
  return request<{ ok: boolean }>({ url: `/bots/fingerprints/${id}`, method: 'put', data });
}

/** 删除恶意指纹 */
export function deleteBotFingerprint(id: number) {
  return request<{ ok: boolean }>({ url: `/bots/fingerprints/${id}`, method: 'delete' });
}

/** 爬虫画像库列表 */
export function fetchBotProfiles() {
  return request<Api.Waf.BotProfile[]>({ url: '/bots/profiles' });
}

/** 新建爬虫画像 */
export function createBotProfile(data: Record<string, unknown>) {
  return request<{ ok: boolean; id: number }>({ url: '/bots/profiles', method: 'post', data });
}

/** 更新爬虫画像 */
export function updateBotProfile(id: number, data: Record<string, unknown>) {
  return request<{ ok: boolean }>({ url: `/bots/profiles/${id}`, method: 'put', data });
}

/** 删除爬虫画像 */
export function deleteBotProfile(id: number) {
  return request<{ ok: boolean }>({ url: `/bots/profiles/${id}`, method: 'delete' });
}

/** 爬虫访问记录 */
export function fetchBotLogs(params: Record<string, string | number>) {
  return request<Api.Waf.PageResult<Api.Waf.BotLog>>({ url: '/bots/logs', params });
}

/** 爬虫记录详情（含请求头/请求体证据） */
export function fetchBotLogDetail(id: number) {
  return request<Api.Waf.BotLog>({ url: `/bots/logs/${id}` });
}

/** 消费爬虫记录队列 */
export function consumeBotLogs() {
  return request<{ status: string; consumed: number }>({ url: '/bots/consume', method: 'post' });
}

/** 爬虫统计总览 */
export function fetchBotStats() {
  return request<{ total: number; real: number; fake: number; tools: number; malicious_ip: number; malicious_fp: number }>({
    url: '/bots/stats'
  });
}

/** 爬虫聚合排行（dim: ip | ua | fingerprint | profile） */
export function fetchBotTop(dim: string, limit = 20) {
  return request<{ items: { key: string; count: number }[] }>({ url: '/bots/top', params: { dim, limit } });
}

/** JA4 客户端指纹查询识别（精确 → ja4_ac 前缀） */
export function fetchJa4Lookup(ja4: string) {
  return request<{ matched: boolean; match?: string; profile?: { name: string; category: string } }>({
    url: '/ja4/lookup',
    params: { ja4 }
  });
}

/** JA4 客户端指纹库列表 */
export function fetchJa4Profiles(category = '') {
  return request<Api.Waf.Ja4Profile[]>({ url: '/ja4/profiles', params: { category } });
}

/** 新建 JA4 客户端指纹 */
export function createJa4Profile(data: Record<string, unknown>) {
  return request<{ ok: boolean; id: number }>({ url: '/ja4/profiles', method: 'post', data });
}

/** 更新 JA4 客户端指纹 */
export function updateJa4Profile(id: number, data: Record<string, unknown>) {
  return request<{ ok: boolean }>({ url: `/ja4/profiles/${id}`, method: 'put', data });
}

/** 删除 JA4 客户端指纹 */
export function deleteJa4Profile(id: number) {
  return request<{ ok: boolean }>({ url: `/ja4/profiles/${id}`, method: 'delete' });
}

/** 导出恶意 JA4 情报（CSV 订阅格式） */
export function exportJa4Malware() {
  return request<string>({ url: '/ja4/export', responseType: 'blob' } as never);
}

/** 爬虫趋势 */
export function fetchBotTrend(days = 7) {
  return request<{ items: { date: string; total: number; fake: number }[] }>({ url: '/bots/trend', params: { days } });
}

/** 一键把爬虫记录指纹加入恶意指纹库 */
export function blacklistBotLog(id: number) {
  return request<{ ok: boolean; fingerprint_id: number }>({ url: `/bots/logs/${id}/blacklist`, method: 'post' });
}
