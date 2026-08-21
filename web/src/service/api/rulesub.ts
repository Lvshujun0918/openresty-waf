import { request } from '../request';

/** 规则订阅源列表 */
export function fetchRuleSubs() {
  return request<Api.Waf.RuleSubscription[]>({ url: '/rule-subs' });
}

/** 创建规则订阅源 */
export function createRuleSub(data: Partial<Api.Waf.RuleSubscription>) {
  return request<Api.Waf.RuleSubscription>({ url: '/rule-subs', method: 'post', data });
}

/** 更新规则订阅源 */
export function updateRuleSub(id: number, data: Partial<Api.Waf.RuleSubscription>) {
  return request<Api.Waf.RuleSubscription>({ url: `/rule-subs/${id}`, method: 'put', data });
}

/** 删除规则订阅源（同时清理该订阅产生的规则并重新发布） */
export function deleteRuleSub(id: number) {
  return request<{ status: string }>({ url: `/rule-subs/${id}`, method: 'delete' });
}

/** 启用/停用规则订阅源 */
export function setRuleSubEnabled(id: number, enabled: boolean) {
  return request<{ status: string }>({ url: `/rule-subs/${id}/enabled`, method: 'patch', data: { enabled } });
}

/** 立即同步规则订阅源 */
export function syncRuleSub(id: number) {
  return request<{ status: string; imported: number }>({ url: `/rule-subs/${id}/sync`, method: 'post' });
}
