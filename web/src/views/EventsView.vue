<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api } from '@/api'
import type { EventItem, PageResult } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

const events = ref<EventItem[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const group = ref('')
const clientIp = ref('')
const host = ref('')
const action = ref('')
const loading = ref(false)
const message = ref('')

// 攻击类型中文名 + 配色（完整 class 供 Tailwind 扫描）
const groupMeta: Record<string, { label: string; color: string }> = {
  sqli: { label: 'SQL 注入', color: 'bg-destructive' },
  xss: { label: 'XSS 跨站', color: 'bg-warning' },
  rce: { label: '远程执行', color: 'bg-purple-500' },
  lfi: { label: '文件包含', color: 'bg-orange-500' },
  ssrf: { label: 'SSRF', color: 'bg-cyan-500' },
  protocol: { label: '协议异常', color: 'bg-brand-500' },
  leak: { label: '信息泄露', color: 'bg-yellow-500' },
  scanner: { label: '扫描器', color: 'bg-pink-500' },
  custom: { label: '自定义规则', color: 'bg-slate-500' },
}
const groupOptions = ['sqli', 'xss', 'rce', 'lfi', 'ssrf', 'protocol', 'leak', 'scanner', 'custom']

// 时间格式化：2026-08-13T18:28:43+08:00 → 08-13 18:28:43
function fmtTime(t: string) {
  if (!t) return '-'
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '')
}

// 动作判定（事件 status 为 HTTP 状态码：403 即被拦截）
function isBlocked(e: EventItem) {
  return e.status >= 400
}
function geoText(e: EventItem) {
  return [e.country, e.province, e.city].filter(Boolean).join(' ')
}

async function load() {
  loading.value = true
  const params = new URLSearchParams({
    page: String(page.value),
    page_size: String(pageSize.value),
  })
  if (group.value) params.set('group', group.value)
  if (clientIp.value) params.set('client_ip', clientIp.value)
  if (host.value) params.set('host', host.value)
  if (action.value) params.set('action', action.value)
  const res = await api.get<PageResult<EventItem>>(`/events?${params}`)
  events.value = res.items
  total.value = res.total
  loading.value = false
}

async function consume() {
  await api.post('/events/consume')
  message.value = '已触发事件消费'
  await load()
  setTimeout(() => (message.value = ''), 3000)
}

// 进入事件页自动消费一次 Redis 队列，再加载列表（后端同时有定时消费兜底）
onMounted(async () => {
  try {
    await consume()
  } catch {
    await load()
  }
})
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-semibold">攻击事件</h1>
        <p class="text-sm text-muted-foreground">共 {{ total }} 条 · 攻击日志实时入库</p>
      </div>
      <Button variant="outline" @click="consume" :disabled="loading">消费 Redis 队列</Button>
    </div>

    <Card>
      <CardHeader>
        <CardTitle>筛选</CardTitle>
      </CardHeader>
      <CardContent class="flex flex-wrap items-end gap-4">
        <div class="space-y-1.5">
          <Label>攻击类型</Label>
          <select v-model="group" class="h-9 rounded-md border border-input bg-transparent px-3 text-sm">
            <option value="">全部</option>
            <option v-for="g in groupOptions" :key="g" :value="g">{{ groupMeta[g]?.label || g }}</option>
          </select>
        </div>
        <div class="space-y-1.5">
          <Label>处置动作</Label>
          <select v-model="action" class="h-9 rounded-md border border-input bg-transparent px-3 text-sm">
            <option value="">全部</option>
            <option value="block">拦截</option>
            <option value="record">仅记录</option>
          </select>
        </div>
        <div class="space-y-1.5">
          <Label>客户端 IP</Label>
          <Input v-model="clientIp" placeholder="如 192.168.1.1" class="w-44" />
        </div>
        <div class="space-y-1.5">
          <Label>域名 (Host)</Label>
          <Input v-model="host" placeholder="如 example.com" class="w-44" />
        </div>
        <Button @click="page = 1; load()" :disabled="loading">查询</Button>
        <span v-if="message" class="text-sm text-muted-foreground">{{ message }}</span>
      </CardContent>
    </Card>

    <Card>
      <CardContent class="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>时间</TableHead>
              <TableHead>请求 ID</TableHead>
              <TableHead>攻击来源</TableHead>
              <TableHead>攻击类型</TableHead>
              <TableHead>命中规则</TableHead>
              <TableHead>动作</TableHead>
              <TableHead>方法</TableHead>
              <TableHead>请求</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="e in events" :key="e.id">
              <TableCell class="whitespace-nowrap text-xs text-muted-foreground">{{ fmtTime(e.time) }}</TableCell>
              <TableCell>
                <span class="font-mono text-[11px] text-muted-foreground" :title="e.req_id || ''">{{ (e.req_id || '-').slice(-12) }}</span>
              </TableCell>
              <TableCell>
                <div class="font-mono text-xs">{{ e.client_ip }}</div>
                <div v-if="e.country" class="flex items-center gap-1 text-[11px] text-muted-foreground">
                  <span class="h-1 w-1 rounded-full bg-brand-400" />
                  {{ geoText(e) }}
                </div>
              </TableCell>
              <TableCell>
                <Badge :class="`${groupMeta[e.group]?.color || 'bg-muted'} text-white border-transparent`">
                  {{ groupMeta[e.group]?.label || e.group }}
                </Badge>
              </TableCell>
              <TableCell>
                <div class="font-mono text-xs">{{ e.rule_id }}</div>
                <div class="max-w-[180px] truncate text-[11px] text-muted-foreground">{{ e.msg }}</div>
              </TableCell>
              <TableCell>
                <Badge
                  :class="isBlocked(e) ? 'bg-destructive text-destructive-foreground' : 'bg-muted text-muted-foreground'"
                  class="border-transparent"
                >
                  {{ isBlocked(e) ? '拦截' : '记录' }}
                </Badge>
              </TableCell>
              <TableCell>
                <span class="rounded border border-border px-1.5 py-0.5 font-mono text-[11px]">{{ e.method || '-' }}</span>
              </TableCell>
              <TableCell>
                <div class="max-w-[260px] truncate text-xs">
                  <span class="text-muted-foreground">{{ e.host || '' }}</span>
                  <span class="font-mono">{{ e.uri }}</span>
                </div>
              </TableCell>
            </TableRow>
            <TableRow v-if="events.length === 0">
              <TableCell colspan="8" class="py-8 text-center text-muted-foreground">
                暂无数据，可先触发一次攻击或点击"消费 Redis 队列"
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </CardContent>
    </Card>

    <div class="flex items-center justify-between">
      <span class="text-sm text-muted-foreground">第 {{ page }} 页 / 共 {{ Math.ceil(total / pageSize) }} 页</span>
      <div class="flex gap-2">
        <Button variant="outline" size="sm" :disabled="page <= 1" @click="page--; load()">上一页</Button>
        <Button variant="outline" size="sm" :disabled="page * pageSize >= total" @click="page++; load()">下一页</Button>
      </div>
    </div>
  </div>
</template>
