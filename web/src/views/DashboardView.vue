<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from '@/api'
import type { EventItem, Rule } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Activity, ListChecks, ShieldCheck, Siren } from 'lucide-vue-next'

const ruleCount = ref(0)
const enabledCount = ref(0)
const eventTotal = ref(0)
const recentEvents = ref<EventItem[]>([])
const groupCounts = ref<Record<string, number>>({})
const groups = ['sqli', 'xss', 'rce', 'lfi', 'ssrf', 'protocol', 'leak', 'scanner'] as const

// 防护状态（从后台运行配置读取）
const mode = ref('active')
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

// 攻击类型语义配色（完整 class 供 Tailwind 扫描）
const groupMeta: Record<string, { color: string; label: string }> = {
  sqli: { color: 'bg-destructive', label: 'SQL 注入' },
  xss: { color: 'bg-warning', label: 'XSS 跨站' },
  rce: { color: 'bg-purple-500', label: '远程执行' },
  lfi: { color: 'bg-orange-500', label: '文件包含' },
  ssrf: { color: 'bg-cyan-500', label: 'SSRF' },
  protocol: { color: 'bg-brand-500', label: '协议异常' },
  leak: { color: 'bg-yellow-500', label: '信息泄露' },
  scanner: { color: 'bg-pink-500', label: '扫描器' },
}

const statCards = [
  { icon: ListChecks, label: '拦截规则总数', key: 'ruleCount', tint: 'from-brand-500 to-brand-600' },
  { icon: ShieldCheck, label: '启用规则', key: 'enabledCount', tint: 'from-emerald-500 to-emerald-600' },
  { icon: Siren, label: '攻击事件累计', key: 'eventTotal', tint: 'from-rose-500 to-rose-600' },
] as const

const maxGroup = computed(() => Math.max(1, ...groups.map((g) => groupCounts.value[g] ?? 0)))

async function load() {
  const rules = await api.get<Rule[]>('/rules')
  ruleCount.value = rules.length
  enabledCount.value = rules.filter((r) => r.enabled).length

  const ev = await api.get<{ total: number; items: EventItem[] }>('/events?page=1&page_size=5')
  eventTotal.value = ev.total
  recentEvents.value = ev.items

  for (const g of groups) {
    const r = await api.get<{ total: number }>(`/events?group=${g}&page=1&page_size=1`)
    groupCounts.value[g] = r.total
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
    <!-- 防护状态横幅（签名元素） -->
    <div class="relative overflow-hidden rounded-xl border bg-card shadow-sm">
      <div class="absolute inset-y-0 left-0 w-1.5 bg-gradient-to-b from-brand-500 to-brand-600" />
      <div class="flex flex-wrap items-center justify-between gap-4 py-4 pl-6 pr-5">
        <div class="flex items-center gap-3">
          <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-brand-50 text-brand-600">
            <Activity class="h-5 w-5" />
          </div>
          <div>
            <div class="flex items-center gap-2">
              <span class="text-base font-semibold">WAF 防护状态</span>
              <Badge :class="modeMeta[mode]?.badge || modeMeta.active.badge" class="border-transparent">
                {{ modeMeta[mode]?.label || modeMeta.active.label }}
              </Badge>
            </div>
            <p class="text-sm text-muted-foreground">{{ modeMeta[mode]?.desc || modeMeta.active.desc }}</p>
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

    <!-- 统计卡 -->
    <div class="grid gap-4 md:grid-cols-3">
      <Card
        v-for="card in statCards"
        :key="card.key"
        class="relative overflow-hidden border-border/70 shadow-sm transition-shadow hover:shadow-md"
      >
        <div class="absolute inset-x-0 top-0 h-1 bg-gradient-to-r" :class="card.tint" />
        <CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardDescription>{{ card.label }}</CardDescription>
          <div class="flex h-8 w-8 items-center justify-center rounded-md bg-muted text-muted-foreground">
            <component :is="card.icon" class="h-4 w-4" />
          </div>
        </CardHeader>
        <CardContent>
          <CardTitle class="text-3xl font-bold tracking-tight">{{ card.key === 'ruleCount' ? ruleCount : card.key === 'enabledCount' ? enabledCount : eventTotal }}</CardTitle>
        </CardContent>
      </Card>
    </div>

    <div class="grid gap-4 lg:grid-cols-2">
      <!-- 攻击类型分布 -->
      <Card class="border-border/70 shadow-sm">
        <CardHeader>
          <CardTitle class="text-base">攻击类型分布</CardTitle>
          <CardDescription>按拦截规则分组统计</CardDescription>
        </CardHeader>
        <CardContent class="space-y-2.5">
          <div
            v-for="g in groups"
            :key="g"
            class="flex items-center gap-3 rounded-lg border border-border/60 px-3 py-2"
          >
            <span class="h-2.5 w-2.5 shrink-0 rounded-full" :class="groupMeta[g]?.color || 'bg-muted-foreground'" />
            <span class="w-20 shrink-0 text-sm font-medium">{{ groupMeta[g]?.label || g }}</span>
            <div class="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
              <div
                class="h-full rounded-full transition-all"
                :class="groupMeta[g]?.color || 'bg-muted-foreground'"
                :style="{ width: `${Math.round(((groupCounts[g] ?? 0) / maxGroup) * 100)}%` }"
              />
            </div>
            <span class="w-10 shrink-0 text-right text-sm font-semibold tabular-nums">{{ groupCounts[g] ?? 0 }}</span>
          </div>
        </CardContent>
      </Card>

      <!-- 近期攻击事件 -->
      <Card class="border-border/70 shadow-sm">
        <CardHeader>
          <CardTitle class="text-base">近期攻击事件</CardTitle>
          <CardDescription>最近被拦截的请求</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>时间</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>类型</TableHead>
                <TableHead>规则</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow v-for="e in recentEvents" :key="e.id">
                <TableCell class="whitespace-nowrap text-xs text-muted-foreground">{{ e.time }}</TableCell>
                <TableCell class="font-mono text-xs">{{ e.client_ip }}</TableCell>
                <TableCell>
                  <span class="inline-flex items-center gap-1.5">
                    <span class="h-1.5 w-1.5 rounded-full" :class="groupMeta[e.group]?.color || 'bg-muted-foreground'" />
                    <span class="text-xs">{{ e.group }}</span>
                  </span>
                </TableCell>
                <TableCell class="font-mono text-xs text-muted-foreground">{{ e.rule_id }}</TableCell>
              </TableRow>
              <TableRow v-if="recentEvents.length === 0">
                <TableCell colspan="4" class="text-center text-muted-foreground py-8">
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
