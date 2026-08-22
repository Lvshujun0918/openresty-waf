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
      /** 是否 WAF 真正拦截（404 等后端状态码不算） */
      blocked?: boolean;
      /** JA4 TLS 指纹 */
      ja4?: string;
      /** JA4H HTTP 客户端指纹 */
      ja4h?: string;
      /** 人工标记误报（命中率统计排除） */
      false_positive?: boolean;
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
      /** 手动输入的 IP/CIDR 列表（每行一个），与 url 二选一 */
      data?: string;
      type: 'whitelist' | 'blacklist';
      /** 订阅目标：ip（黑白名单）| fingerprint（恶意指纹库）| bot_profile（爬虫画像库） */
      target: string;
      interval_min: number;
      enabled: boolean;
      last_sync_at?: string;
      last_status?: string;
      last_count?: number;
      created_at?: string;
      updated_at?: string;
    }

    /** 规则订阅源（远程规则集同步入库，格式与 /rules/export 导出一致） */
    interface RuleSubscription {
      id: number;
      name: string;
      url: string;
      /** 同步后自动发布规则集（默认 false，需手动发布） */
      auto_publish: boolean;
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
      /** JA4 TLS 指纹 */
      ja4?: string;
      /** JA4H HTTP 客户端指纹 */
      ja4h?: string;
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
      /** JA4 TLS 指纹 */
      ja4?: string;
      /** JA4H HTTP 客户端指纹 */
      ja4h?: string;
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

    /** 规则灰度发布状态 */
    interface CanaryStatus {
      active: boolean;
      version?: string;
      percent?: number;
      ips?: string[];
    }

    /** 封禁条目 */
    interface BanEntry {
      ip: string;
      ua?: string;
      expires_at: number | null;
      permanent: boolean;
    }

    /** 引擎健康状态 */
    interface EngineStatus {
      pid: number;
      engine_version: string;
      ruleset_version: string;
      config_version: string;
      trigger_version: string;
      last_seen: number;
      online: boolean;
      rule_synced: boolean;
    }

    /** 告警通知通道 */
    interface AlertChannel {
      id: number;
      name: string;
      type: string;
      webhook_url: string;
      smtp_host: string;
      smtp_port: number;
      smtp_user: string;
      smtp_from: string;
      enabled: boolean;
    }

    /** 告警规则 */
    interface AlertRule {
      id: number;
      name: string;
      type: string;
      window_sec: number;
      threshold: number;
      action: string;
      channel_id: number;
      cooldown_sec: number;
      enabled: boolean;
      last_triggered_at: string | null;
    }

    /** 操作审计日志 */
    interface AuditLog {
      id: number;
      username: string;
      action: string;
      method: string;
      path: string;
      detail: string;
      client_ip: string;
      success: boolean;
      created_at: string;
    }

    /** 规则性能画像行（引擎上报的各规则评估耗时统计） */
    interface RulePerfRow {
      rule_id: string;
      /** 联查的规则名称（规则已删除时为空字符串） */
      name: string;
      /** 联查的规则分组（规则已删除时为空字符串） */
      group: string;
      /** 联查的规则命中提示信息 */
      message: string;
      /** 联查的规则启用状态（规则已删除时为 false） */
      enabled: boolean;
      /** 累计评估次数 */
      hits: number;
      /** 平均耗时（微秒） */
      avg_us: number;
      /** 最大耗时（微秒） */
      max_us: number;
      /** 累计耗时（微秒） */
      total_us: number;
      updated_at: string;
    }

    /** 引擎报错汇总行（ERR/WARN 级，由引擎异步上报） */
    interface ErrorLogRow {
      id: number;
      time: string;
      /** error / warn */
      level: string;
      /** 来源模块：access/init/engine/operators/cc/challenge/upload/ja4/log 等 */
      source: string;
      message: string;
      req_id: string;
      client_ip: string;
      host: string;
      uri: string;
      engine_version: string;
      created_at: string;
    }

    /** 近 24 小时报错统计 */
    interface ErrorStats {
      error: number;
      warn: number;
    }

    /** 流量统计汇总 */
    interface TrafficSummary {
      total: number;
      blocked: number;
      block_rate: number;
      attacks: number;
      unique_ips: number;
      avg_response_ms: number;
    }

    /** 流量时间序列点 */
    interface TrafficPoint {
      label: string;
      total: number;
      blocked: number;
      attacks: number;
    }

    /** 名称-计数对（状态分布/Top 列表） */
    interface NameCount {
      name: string;
      count: number;
      blocked: number;
    }

    /** 流量统计报告 */
    interface TrafficStatReport {
      hours: number;
      summary: TrafficSummary;
      series: TrafficPoint[];
      status_dist: NameCount[];
      top_ips: NameCount[];
      top_uris: NameCount[];
      top_hosts: NameCount[];
    }

    /** API Token（不含哈希，明文仅创建时返回一次） */
    interface ApiToken {
      id: number;
      name: string;
      prefix: string;
      last_used_at: string | null;
      revoked_at: string | null;
      created_at: string;
    }

    /** 后台用户（/users，仅超管可见） */
    interface UserRow {
      id: number;
      username: string;
      /** 角色：super 超管 / ops 运营 / viewer 只读 */
      role: string;
      totp_enabled: boolean;
      created_at: string;
      updated_at: string;
    }

    /** 登录会话 */
    interface Session {
      jti: string;
      user_id: number;
      username: string;
      ip: string;
      ua: string;
      created_at: number;
    }

    /** 恶意指纹条目 */
    interface BotFingerprint {
      id: number;
      name: string;
      value: string;
      match: string;
      description: string;
      enabled: boolean;
    }

    /** 爬虫画像 */
    interface BotProfile {
      id: number;
      name: string;
      ua: string;
      ips: string;
      engine: boolean;
      enabled: boolean;
      sort_order: number;
    }

    /** JA4 客户端指纹库条目 */
    interface Ja4Profile {
      id: number;
      ja4: string;
      ac_prefix?: string;
      name: string;
      category: string;
      description?: string;
      enabled: boolean;
      source?: string;
    }

    /** 爬虫访问记录 */
    interface BotLog {
      id: number;
      time: string;
      req_id: string;
      client_ip: string;
      country?: string;
      province?: string;
      city?: string;
      method: string;
      host: string;
      uri: string;
      ua: string;
      fingerprint: string;
      /** JA4 TLS 指纹（TLS 连接） */
      ja4?: string;
      /** JA4H HTTP 客户端指纹 */
      ja4h?: string;
      /** 命中指纹来源（ja4 | http） */
      fp_source?: string;
      /** 请求头 JSON（name/value 数组） */
      headers?: string;
      /** 请求体（最多 8KB） */
      body?: string;
      /** JA4 客户端识别（查询附加） */
      client_name?: string;
      client_category?: string;
      ja4_match?: string;
      profile: string;
      engine: boolean;
      fake: boolean;
      malicious_ip: boolean;
      malicious_fp: string;
      status: number;
    }
  }
}
