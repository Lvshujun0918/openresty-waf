declare namespace Api {
  /**
   * namespace Waf
   *
   * backend api module: "waf"
   */
  namespace Waf {
    interface PageResult<T> {
      total: number;
      page: number;
      page_size: number;
      items: T[];
    }

    /** 攻击事件 */
    interface EventItem {
      id: number;
      time: string;
      req_id?: string;
      client_ip: string;
      country?: string;
      province?: string;
      city?: string;
      method: string;
      host: string;
      uri: string;
      rule_id: string;
      rule_ids?: string;
      /** 命中规则详情 JSON（id/group/msg/severity） */
      rules?: string;
      /** 请求头 JSON */
      headers?: string;
      /** 请求体 */
      body?: string;
      group: string;
      msg: string;
      severity: number;
      status: number;
      created_at?: string;
    }

    /** 流量记录 */
    interface TrafficItem {
      id: number;
      time: string;
      req_id?: string;
      client_ip: string;
      country?: string;
      province?: string;
      city?: string;
      method: string;
      host: string;
      uri: string;
      status: number;
      user_agent: string;
      attack: boolean;
      rule_ids: string;
      response_time: number;
      created_at?: string;
    }

    /** 规则 */
    interface Rule {
      id: number;
      rule_id: string;
      name: string;
      group: string;
      phase: string;
      severity: number;
      enabled: boolean;
      operator: string;
      pattern: string;
      transforms: string;
      vars: string;
      actions: string;
      status: number;
      message: string;
      sort_order: number;
      created_at?: string;
      updated_at?: string;
    }

    /** IP 列表订阅 */
    interface IpListSub {
      id: number;
      name: string;
      url: string;
      type: 'whitelist' | 'blacklist';
      interval_min: number;
      enabled: boolean;
      last_sync_at?: string;
      last_status?: string;
      last_count?: number;
      created_at?: string;
      updated_at?: string;
    }

    /** 人机验证事件 */
    interface ChallengeItem {
      id: number;
      time: string;
      req_id?: string;
      client_ip: string;
      country?: string;
      province?: string;
      city?: string;
      action: string;
      method?: string;
      host?: string;
      uri: string;
      /** 触发的触发规则名称 */
      rule_name?: string;
      /** 请求头 JSON（name/value 数组） */
      headers?: string;
      /** 请求体（最多 8KB） */
      body?: string;
      created_at?: string;
    }

    /** CC 触发事件 */
    interface CcLogItem {
      id: number;
      time: string;
      req_id?: string;
      client_ip: string;
      country?: string;
      province?: string;
      city?: string;
      method?: string;
      host?: string;
      uri: string;
      /** 触发的触发规则名称 */
      rule_name?: string;
      /** 请求头 JSON（name/value 数组） */
      headers?: string;
      /** 请求体（最多 8KB） */
      body?: string;
      status: number;
      created_at?: string;
    }

    /** 触发条件：对请求参数筛选（host/path/ua/ip/method/header/args） */
    interface TriggerCondition {
      field: string;
      operator: string;
      value: string;
      header?: string;
      negate?: boolean;
    }

    /** 触发规则：条件（AND/OR）命中后执行对应动作（challenge/exempt/cc） */
    interface TriggerRule {
      id: number;
      name: string;
      kind: string;
      match_logic: string;
      enabled: boolean;
      sort_order: number;
      /** TriggerCondition JSON 数组 */
      conditions: string;
      /** 动作配置 JSON（cc: rate/ban_duration；challenge: mode） */
      config?: string;
      created_at?: string;
      updated_at?: string;
    }

    /** 仪表盘聚合统计 */
    interface DashboardStats {
      today: { request: number; attack: number; intercept_24h: number };
      total: { events: number; traffic: number };
      qps: number;
      attack_trend: { date: string; attack: number }[];
      groups: { group: string; count: number }[];
      top_ips: { client_ip: string; count: number; country: string; province: string; city: string }[];
      countries: { country: string; count: number }[];
    }

    /** 规则测试 */
    interface RuleTestReq {
      rule_id: string;
      request: {
        method: string;
        uri: string;
        body: string;
        content_type: string;
        headers?: Record<string, string>;
        cookies?: string;
        client_ip?: string;
      };
    }

    /** 规则发布历史（支持一键回滚） */
    interface PublishHistory {
      id: number;
      kind: string;
      version: string;
      rule_count: number;
      created_at: string;
    }
  }
}
