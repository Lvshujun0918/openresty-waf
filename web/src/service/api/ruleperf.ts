import { request } from '../request';

/** 规则性能画像列表（按累计耗时降序） */
export function fetchRulePerf(limit = 100) {
  return request<{ items: Api.Waf.RulePerfRow[] }>({ url: '/rules/perf', params: { limit } });
}

/** 触发后台立即消费引擎上报队列 */
export function consumeRulePerf() {
  return request<{ status: string; consumed: number }>({ url: '/rules/perf/consume', method: 'post' });
}

/** 清空规则性能统计 */
export function resetRulePerf() {
  return request<{ status: string }>({ url: '/rules/perf', method: 'delete' });
}
