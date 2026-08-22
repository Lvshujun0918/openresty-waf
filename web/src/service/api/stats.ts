import { request } from '../request';

/** 流量统计报告（汇总/时间序列/状态分布/TopN） */
export function fetchTrafficStatReport(hours = 24) {
  return request<Api.Waf.TrafficStatReport>({ url: '/stats/traffic', params: { hours } });
}
