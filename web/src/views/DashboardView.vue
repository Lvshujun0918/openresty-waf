<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from '@/api'
import type { EventItem, Rule } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Activity, Flame, Globe, ShieldCheck, Siren } from 'lucide-vue-next'

// —— 基础状态 ——
const mode = ref('active')
const ruleCount = ref(0)
const enabledCount = ref(0)
const recentEvents = ref<EventItem[]>([])
const trendDays = 14

// —— 仪表盘聚合统计（GET /dashboard/stats，一次拉取） ——
interface DashStats {
  today: { request: number; attack: number; intercept_24h: number }
  total: { events: number; traffic: number }
  qps: number
  attack_trend: { date: string; attack: number }[]
  groups: { group: string; count: number }[]
  top_ips: { client_ip: string; count: number; country: string; province: string; city: string }[]
  countries: { country: string; count: number }[]
}
const stats = ref<DashStats | null>(null)
// 请求趋势（全量流量记录开启时才有数据）
const reqTrend = ref<{ date: string; total: number; attack: number }[]>([])

// 攻击类型中文名 + 配色（含 SVG hex）
const groupMeta: Record<string, { label: string; color: string; hex: string }> = {
  sqli: { label: 'SQL 注入', color: 'bg-destructive', hex: '#ef4444' },
  xss: { label: 'XSS 跨站', color: 'bg-warning', hex: '#f59e0b' },
  rce: { label: '远程执行', color: 'bg-purple-500', hex: '#a855f7' },
  lfi: { label: '文件包含', color: 'bg-orange-500', hex: '#f97316' },
  ssrf: { label: 'SSRF', color: 'bg-cyan-500', hex: '#06b6d4' },
  protocol: { label: '协议异常', color: 'bg-brand-500', hex: '#3b82f6' },
  leak: { label: '信息泄露', color: 'bg-yellow-500', hex: '#eab308' },
  scanner: { label: '扫描器', color: 'bg-pink-500', hex: '#ec4899' },
  custom: { label: '自定义规则', color: 'bg-slate-500', hex: '#64748b' },
}

// —— 趋势合并：攻击（事件表，始终有）+ 请求（流量表，可选） ——
const trend = computed(() => {
  const atk = stats.value?.attack_trend ?? []
  const byDate = new Map(reqTrend.value.map((p) => [p.date, p.total]))
  return atk.map((p) => ({ date: p.date, total: byDate.get(p.date) ?? 0, attack: p.attack }))
})
const trendHasTotal = computed(() => trend.value.some((p) => p.total > 0))

// SVG 趋势图几何
const trendW = 600
const trendH = 180
const pad = { l: 36, r: 10, t: 12, b: 24 }
const trendMax = computed(() => Math.max(1, ...trend.value.map((p) => Math.max(p.total, p.attack))))
function trendPoints(key: 'total' | 'attack') {
  const n = trend.value.length
  return trend.value.map((p, i) => {
    const x = pad.l + (n <= 1 ? 0 : (i / (n - 1)) * (trendW - pad.l - pad.r))
    const y = trendH - pad.b - (p[key] / trendMax.value) * (trendH - pad.t - pad.b)
    return [x, y] as const
  })
}
function trendPath(key: 'total' | 'attack') {
  const pts = trendPoints(key)
  if (pts.length === 0) return ''
  return pts.map(([x, y], i) => (i === 0 ? `M${x},${y}` : `L${x},${y}`)).join(' ')
}
function trendAreaPath(key: 'total' | 'attack') {
  const pts = trendPoints(key)
  if (pts.length === 0) return ''
  const line = pts.map(([x, y], i) => (i === 0 ? `M${x},${y}` : `L${x},${y}`)).join(' ')
  const last = pts[pts.length - 1]
  const first = pts[0]
  return `${line} L${last[0]},${trendH - pad.b} L${first[0]},${trendH - pad.b} Z`
}
function trendXTicks() {
  const n = trend.value.length
  const idxs = n <= 2 ? trend.value.map((_, i) => i) : [0, Math.floor((n - 1) / 2), n - 1]
  return idxs.map((i) => {
    const x = pad.l + (n <= 1 ? 0 : (i / (n - 1)) * (trendW - pad.l - pad.r))
    const label = trend.value[i]?.date?.slice(5) ?? '' // MM-DD
    return { x, label }
  })
}

// —— 环形图（Web 攻击分布） ——
const donutR = 40
const donutC = 2 * Math.PI * donutR
const donutSegs = computed(() => {
  const gs = stats.value?.groups ?? []
  const total = gs.reduce((s, g) => s + g.count, 0)
  if (total <= 0) return []
  let acc = 0
  return gs.map((g) => {
    const frac = g.count / total
    const seg = { ...g, frac, offset: acc, dash: frac * donutC }
    acc += frac * donutC
    return seg
  })
})
const donutTotal = computed(() => (stats.value?.groups ?? []).reduce((s, g) => s + g.count, 0))

// —— Top IP / 归属地条形最大值 ——
const maxTopIP = computed(() => Math.max(1, ...(stats.value?.top_ips ?? []).map((x) => x.count)))
const maxCountry = computed(() => Math.max(1, ...(stats.value?.countries ?? []).map((x) => x.count)))

// 防护状态（从后台运行配置读取）
const modeMeta: Record<string, { label: string; desc: string; dot: string; badge: string }> = {
  active: {
    label: '拦截模式',
    desc: '命中规则即阻断，全量防护已开启',
    dot: 'bg-success',
    badge: 'bg-success text-success-foreground',
  },
  detect: {
    label: '监控模式',
    desc: '仅记录攻击日志，不阻断请求',
    dot: 'bg-warning',
    badge: 'bg-warning text-warning-foreground',
  },
  off: {
    label: '放行模式',
    desc: '旁路运行，不执行检测',
    dot: 'bg-muted-foreground',
    badge: 'bg-muted text-muted-foreground',
  },
}

// 数字格式化（k/M 缩写）
function formatNum(n: number) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M'
  if (n >= 1000) return (n / 1000).toFixed(1) + 'k'
  return String(n)
}

// 归属地文本拼接
function geoText(c?: string, p?: string, ct?: string) {
  return [c, p, ct].filter(Boolean).join(' ')
}

// 动作判定（事件 status 为 HTTP 状态码：403 即被拦截）
function isBlocked(e: EventItem) {
  return e.status >= 400
}

// 统计卡（雷池风格：大数字 + 图标 + 副信息）
const statCards = computed(() => [
  {
    icon: Globe,
    label: '今日请求',
    value: formatNum(stats.value?.today.request ?? 0),
    sub: `累计请求 ${formatNum(stats.value?.total.traffic ?? 0)}`,
    tint: 'from-brand-500 to-brand-600',
    iconBg: 'bg-brand-50 text-brand-600',
  },
  {
    icon: Siren,
    label: '今日拦截',
    value: formatNum(stats.value?.today.attack ?? 0),
    sub: `累计拦截 ${formatNum(stats.value?.total.events ?? 0)}`,
    tint: 'from-rose-500 to-rose-600',
    iconBg: 'bg-rose-50 text-rose-600',
  },
  {
    icon: Flame,
    label: '24H 拦截',
    value: formatNum(stats.value?.today.intercept_24h ?? 0),
    sub: '近 24 小时命中攻击',
    tint: 'from-orange-500 to-amber-500',
    iconBg: 'bg-orange-50 text-orange-600',
  },
  {
    icon: Activity,
    label: '实时 QPS',
    value: (stats.value?.qps ?? 0).toFixed(1),
    sub: '近 60 秒请求均值',
    tint: 'from-emerald-500 to-emerald-600',
    iconBg: 'bg-emerald-50 text-emerald-600',
  },
])

async function load() {
  try {
    stats.value = await api.get<DashStats>(`/dashboard/stats?days=${trendDays}`)
  } catch {
    stats.value = null
  }
  try {
    const rules = await api.get<Rule[]>('/rules')
    ruleCount.value = rules.length
    enabledCount.value = rules.filter((r) => r.enabled).length
  } catch {
    /* 规则读取失败时忽略 */
  }
  try {
    const ev = await api.get<{ total: number; items: EventItem[] }>('/events?page=1&page_size=6')
    recentEvents.value = ev.items
  } catch {
    /* 事件读取失败时忽略 */
  }
  try {
    const tr = await api.get<{ items: { date: string; total: number; attack: number }[] }>(
      `/traffic/trend?days=${trendDays}`,
    )
    reqTrend.value = tr.items || []
  } catch {
    reqTrend.value = []
  }
  try {
    const cfg = await api.get<{ config: { mode?: string } }>('/config')
    mode.value = cfg.config?.mode || 'active'
  } catch {
    /* 配置读取失败时保持默认 */
  }
}

onMounted(load)
</script>

<template>
  <div class="space-y-6">
    <!-- 安全态势横幅 -->
    <div class="relative overflow-hidden rounded-xl border bg-card shadow-sm">
      <div class="absolute inset-y-0 left-0 w-1.5 bg-gradient-to-b from-brand-500 to-brand-600" />
      <div class="flex flex-wrap items-center justify-between gap-4 py-4 pl-6 pr-5">
        <div class="flex items-center gap-3">
          <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-brand-50 text-brand-600">
            <ShieldCheck class="h-5 w-5" />
          </div>
          <div>
            <div class="flex items-center gap-2">
              <span class="text-base font-semibold">安全态势</span>
              <Badge :class="modeMeta[mode]?.badge || modeMeta.active.badge" class="border-transparent">
                {{ modeMeta[mode]?.label || modeMeta.active.label }}
              </Badge>
            </div>
            <p class="text-sm text-muted-foreground">
              {{ modeMeta[mode]?.desc || modeMeta.active.desc }} · 规则 {{ ruleCount }} 条 / 启用 {{ enabledCount }} 条
            </p>
          </div>
        </div>
        <div class="flex items-center gap-4 text-sm">
          <div class="flex items-center gap-1.5">
            <span class="h-2 w-2 rounded-full" :class="modeMeta[mode]?.dot || 'bg-success'" />
            规则引擎运行中
          </div>
          <span class="text-muted-foreground">配置变更 5 秒内热更新生效</span>
        </div>
      </div>
    </div>

    <!-- 统计卡（雷池风格） -->
    <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <Card
        v-for="card in statCards"
        :key="card.label"
        class="relative overflow-hidden border-border/70 shadow-sm transition-shadow hover:shadow-md"
      >
        <div class="absolute inset-x-0 top-0 h-1 bg-gradient-to-r" :class="card.tint" />
        <CardContent class="pt-5">
          <div class="flex items-start justify-between">
            <div>
              <p class="text-sm text-muted-foreground">{{ card.label }}</p>
              <p class="mt-2 text-3xl font-bold tracking-tight tabular-nums">{{ card.value }}</p>
              <p class="mt-1 text-xs text-muted-foreground">{{ card.sub }}</p>
            </div>
            <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl" :class="card.iconBg">
              <component :is="card.icon" class="h-5 w-5" />
            </div>
          </div>
        </CardContent>
      </Card>
    </div>

    <!-- 请求与攻击趋势 -->
    <Card class="border-border/70 shadow-sm">
      <CardHeader class="flex flex-row items-center justify-between">
        <div>
          <CardTitle class="text-base">请求与攻击趋势</CardTitle>
          <CardDescription>近 {{ trendDays }} 天攻击命中（事件表，始终有）+ 全量请求（需开启全量记录）</CardDescription>
        </div>
        <div class="flex items-center gap-4 text-xs text-muted-foreground">
          <span class="flex items-center gap-1.5"><span class="h-2 w-2 rounded-full bg-brand-500" /> 请求</span>
          <span class="flex items-center gap-1.5"><span class="h-2 w-2 rounded-full bg-rose-500" /> 攻击</span>
        </div>
      </CardHeader>
      <CardContent>
        <svg v-if="trend.length > 0" :viewBox="`0 0 ${trendW} ${trendH}`" class="w-full">
          <!-- 水平网格线 -->
          <line v-for="i in [0, 1, 2]" :key="i"
            :x1="pad.l" :x2="trendW - pad.r"
            :y1="pad.t + (i / 2) * (trendH - pad.t - pad.b)"
            :y2="pad.t + (i / 2) * (trendH - pad.t - pad.b)"
            stroke="currentColor" stroke-opacity="0.08" stroke-width="1" />
          <defs>
            <linearGradient id="totalGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.28" />
              <stop offset="100%" stop-color="#3b82f6" stop-opacity="0" />
            </linearGradient>
            <linearGradient id="atkGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#f43f5e" stop-opacity="0.2" />
              <stop offset="100%" stop-color="#f43f5e" stop-opacity="0" />
            </linearGradient>
          </defs>
          <path v-if="trendHasTotal" :d="trendAreaPath('total')" fill="url(#totalGrad)" />
          <path v-if="trendHasTotal" :d="trendPath('total')" fill="none" stroke="#3b82f6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          <path :d="trendAreaPath('attack')" fill="url(#atkGrad)" />
          <path :d="trendPath('attack')" fill="none" stroke="#f43f5e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          <!-- X 轴标签 -->
          <text v-for="t in trendXTicks()" :key="t.label" :x="t.x" :y="trendH - 6"
            text-anchor="middle" class="fill-muted-foreground" font-size="10">
            {{ t.label }}
          </text>
        </svg>
        <p v-else class="py-8 text-center text-sm text-muted-foreground">
          暂无趋势数据
        </p>
      </CardContent>
    </Card>

    <div class="grid gap-4 lg:grid-cols-2">
      <!-- Web 攻击分布（环形图） -->
      <Card class="border-border/70 shadow-sm">
        <CardHeader>
          <CardTitle class="text-base">Web 攻击分布</CardTitle>
          <CardDescription>按攻击类型占比统计</CardDescription>
        </CardHeader>
        <CardContent class="flex items-center gap-6">
          <div class="relative h-40 w-40 shrink-0">
            <svg viewBox="0 0 100 100" class="h-full w-full -rotate-90">
              <circle cx="50" cy="50" r="40" fill="none" stroke="currentColor" stroke-opacity="0.08" stroke-width="12" />
              <circle
                v-for="s in donutSegs"
                :key="s.group"
                cx="50" cy="50" r="40" fill="none"
                :stroke="groupMeta[s.group]?.hex || '#64748b'"
                stroke-width="12"
                :stroke-dasharray="`${s.dash} ${donutC - s.dash}`"
                :stroke-dashoffset="-s.offset"
              />
            </svg>
            <div class="absolute inset-0 flex flex-col items-center justify-center">
              <span class="text-2xl font-bold tabular-nums">{{ donutTotal }}</span>
              <span class="text-[11px] text-muted-foreground">攻击事件</span>
            </div>
          </div>
          <div class="min-w-0 flex-1 space-y-2">
            <div
              v-for="s in donutSegs"
              :key="s.group"
              class="flex items-center gap-2 rounded-lg border border-border/60 px-3 py-1.5 text-sm"
            >
              <span class="h-2.5 w-2.5 shrink-0 rounded-sm" :style="{ background: groupMeta[s.group]?.hex || '#64748b' }" />
              <span class="w-20 shrink-0 font-medium">{{ groupMeta[s.group]?.label || s.group }}</span>
              <div class="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                <div
                  class="h-full rounded-full"
                  :style="{ width: `${Math.round(s.frac * 100)}%`, background: groupMeta[s.group]?.hex || '#64748b' }"
                />
              </div>
              <span class="w-16 shrink-0 text-right text-xs tabular-nums text-muted-foreground">{{ s.count }} · {{ Math.round(s.frac * 100) }}%</span>
            </div>
            <p v-if="donutSegs.length === 0" class="py-6 text-center text-sm text-muted-foreground">暂无攻击数据</p>
          </div>
        </CardContent>
      </Card>

      <!-- 攻击来源 Top 10 -->
      <Card class="border-border/70 shadow-sm">
        <CardHeader>
          <CardTitle class="text-base">攻击来源 Top 10</CardTitle>
          <CardDescription>按攻击次数排序（含归属地）</CardDescription>
        </CardHeader>
        <CardContent class="space-y-2.5">
          <div v-for="(ip, i) in (stats?.top_ips ?? [])" :key="ip.client_ip" class="flex items-center gap-3">
            <span class="w-5 shrink-0 text-right text-xs tabular-nums text-muted-foreground">{{ i + 1 }}</span>
            <div class="min-w-0 flex-1">
              <div class="flex items-center justify-between gap-2">
                <span class="truncate font-mono text-xs">{{ ip.client_ip }}</span>
                <span class="shrink-0 text-xs font-semibold tabular-nums">{{ ip.count }}</span>
              </div>
              <div class="mt-0.5 flex items-center gap-2">
                <span v-if="ip.country" class="shrink-0 truncate text-[11px] text-muted-foreground">
                  {{ geoText(ip.country, ip.province, ip.city) }}
                </span>
                <div class="h-1 flex-1 overflow-hidden rounded-full bg-muted">
                  <div class="h-full rounded-full bg-gradient-to-r from-rose-500 to-orange-400" :style="{ width: `${(ip.count / maxTopIP) * 100}%` }" />
                </div>
              </div>
            </div>
          </div>
          <p v-if="(stats?.top_ips ?? []).length === 0" class="py-6 text-center text-sm text-muted-foreground">
            暂无攻击来源数据
          </p>
        </CardContent>
      </Card>
    </div>

    <div class="grid gap-4 lg:grid-cols-2">
      <!-- 攻击来源归属地分布 -->
      <Card class="border-border/70 shadow-sm">
        <CardHeader>
          <CardTitle class="text-base">攻击来源归属地</CardTitle>
          <CardDescription>按国家聚合 Top 8</CardDescription>
        </CardHeader>
        <CardContent class="space-y-2.5">
          <div v-for="c in (stats?.countries ?? [])" :key="c.country" class="flex items-center gap-3">
            <Globe class="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
            <span class="w-28 shrink-0 truncate text-sm">{{ c.country }}</span>
            <div class="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
              <div
                class="h-full rounded-full bg-gradient-to-r from-brand-500 to-brand-600"
                :style="{ width: `${(c.count / maxCountry) * 100}%` }"
              />
            </div>
            <span class="w-10 shrink-0 text-right text-sm tabular-nums text-muted-foreground">{{ c.count }}</span>
          </div>
          <p v-if="(stats?.countries ?? []).length === 0" class="py-6 text-center text-sm text-muted-foreground">
            暂无归属地数据
          </p>
        </CardContent>
      </Card>

      <!-- 近期攻击事件 -->
      <Card class="border-border/70 shadow-sm">
        <CardHeader>
          <CardTitle class="text-base">近期攻击事件</CardTitle>
          <CardDescription>最近被检测到的攻击请求</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>时间</TableHead>
                <TableHead>来源</TableHead>
                <TableHead>类型</TableHead>
                <TableHead>规则</TableHead>
                <TableHead>动作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow v-for="e in recentEvents" :key="e.id">
                <TableCell class="whitespace-nowrap text-xs text-muted-foreground">{{ e.time }}</TableCell>
                <TableCell>
                  <div class="font-mono text-xs">{{ e.client_ip }}</div>
                  <div v-if="e.country" class="text-[11px] text-muted-foreground">{{ geoText(e.country, e.province, e.city) }}</div>
                </TableCell>
                <TableCell>
                  <span class="inline-flex items-center gap-1.5">
                    <span class="h-1.5 w-1.5 rounded-full" :class="groupMeta[e.group]?.color || 'bg-muted-foreground'" />
                    <span class="text-xs">{{ groupMeta[e.group]?.label || e.group }}</span>
                  </span>
                </TableCell>
                <TableCell class="font-mono text-xs text-muted-foreground">{{ e.rule_id }}</TableCell>
                <TableCell>
                  <Badge :class="isBlocked(e) ? 'bg-destructive text-destructive-foreground' : 'bg-muted text-muted-foreground'" class="border-transparent">
                    {{ isBlocked(e) ? '拦截' : '记录' }}
                  </Badge>
                </TableCell>
              </TableRow>
              <TableRow v-if="recentEvents.length === 0">
                <TableCell colspan="5" class="text-center text-muted-foreground py-8">
                  暂无攻击事件，一切正常 🛡️
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
