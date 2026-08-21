import { request } from '../request';

/** 报错汇总分页列表（引擎 ERR/WARN 上报） */
export function fetchErrorLogs(params: Record<string, string | number>) {
  return request<Api.Waf.PageResult<Api.Waf.ErrorLogRow>>({ url: '/errors', params });
}

/** 近 24 小时按级别统计 */
export function fetchErrorStats() {
  return request<Api.Waf.ErrorStats>({ url: '/errors/stats' });
}

/** 手动触发消费引擎上报队列 */
export function consumeErrorLogs() {
  return request<{ status: string; consumed: number }>({ url: '/errors/consume', method: 'post' });
}

/** 清空报错记录 */
export function clearErrorLogs() {
  return request<{ status: string }>({ url: '/errors', method: 'delete' });
}
