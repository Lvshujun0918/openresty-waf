export interface Rule {
  id: number
  rule_id: string
  name: string
  group: string
  phase: string
  severity: number
  enabled: boolean
  operator: string
  pattern: string
  transforms: string
  vars: string
  actions: string
  status: number
  message: string
  site_id: number
  sort_order: number
  created_at?: string
  updated_at?: string
}

export interface EventItem {
  id: number
  time: string
  client_ip: string
  method: string
  host: string
  uri: string
  rule_id: string
  group: string
  msg: string
  severity: number
  status: number
  created_at?: string
}

export interface PageResult<T> {
  total: number
  page: number
  page_size: number
  items: T[]
}

export const RULE_GROUPS = [
  'sqli',
  'xss',
  'rce',
  'lfi',
  'ssrf',
  'protocol',
  'leak',
  'scanner',
  'custom',
] as const
