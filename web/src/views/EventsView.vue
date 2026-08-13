<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from '@/api'
import type { EventItem, PageResult } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { X } from 'lucide-vue-next'
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

// ===== 事件详情弹窗 =====
interface RuleHit { id: string; group: string; msg: string; severity: number }
interface HeaderKV { name: string; value: string }
const detailOpen = ref(false)
const detailLoading = ref(false)
const detail = ref<(EventItem & { rules?: string; headers?: string; body?: string }) | null>(null)

const parsedRules = computed<RuleHit[]>(() => {
  if (!detail.value?.rules) return []
  try { return JSON.parse(detail.value.rules) } catch { return [] }
})
const parsedHeaders = computed<HeaderKV[]>(() => {
  if (!detail.value?.headers) return []
  try { return JSON.parse(detail.value.headers) } catch { return [] }
})
const severityMeta: Record<number, { label: string; cls: string }> = {
  1: { label: '紧急', cls: 'bg-rose-600 text-white' },
  2: { label: '高危', cls: 'bg-destructive text-white' },
  3: { label: '中危', cls: 'bg-warning text-white' },
  4: { label: '低危', cls: 'bg-muted text-muted-foreground' },
}

async function openDetail(e: EventItem) {
  detailOpen.value = true
  detailLoading.value = true
  detail.value = null
  try {
    detail.value = await api.get<EventItem & { rules?: string; headers?: string; body?: string }>(
      `/events/${e.id}`,
    )
  } catch {
    detail.value = null
  } finally {
    detailLoading.value = false
  }
}
function closeDetail() {
  detailOpen.value = false
  detail.value = null
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
              <TableHead>操作</TableHead>
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
              <TableCell>
                <Button variant="outline" size="sm" @click="openDetail(e)">详情</Button>
              </TableCell>
            </TableRow>
            <TableRow v-if="events.length === 0">
              <TableCell colspan="9" class="py-8 text-center text-muted-foreground">
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

    <!-- 事件详情弹窗 -->
    <div
      v-if="detailOpen"
      class="fixed inset-0 z-50 overflow-y-auto bg-black/40 p-4 sm:p-8"
      @click.self="closeDetail"
    >
      <div class="mx-auto w-full max-w-3xl rounded-xl border bg-card shadow-2xl">
        <!-- 头部 -->
        <div class="flex items-center justify-between border-b px-5 py-3.5">
          <div>
            <h2 class="text-base font-semibold">攻击事件详情</h2>
            <p class="font-mono text-[11px] text-muted-foreground">req_id: {{ detail?.req_id || '-' }}</p>
          </div>
          <button
            class="rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            @click="closeDetail"
          >
            <X class="h-5 w-5" />
          </button>
        </div>

        <div class="max-h-[75vh] space-y-6 overflow-y-auto p-5">
          <p v-if="detailLoading" class="py-8 text-center text-sm text-muted-foreground">加载中…</p>

          <template v-if="detail && !detailLoading">
            <!-- 基本信息 -->
            <div class="grid grid-cols-2 gap-x-6 gap-y-2.5 text-sm md:grid-cols-3">
              <div>
                <div class="text-xs text-muted-foreground">时间</div>
                <div>{{ fmtTime(detail.time) }}</div>
              </div>
              <div>
                <div class="text-xs text-muted-foreground">来源 IP</div>
                <div class="font-mono">{{ detail.client_ip }}</div>
              </div>
              <div v-if="detail.country">
                <div class="text-xs text-muted-foreground">归属地</div>
                <div>{{ geoText(detail) }}</div>
              </div>
              <div>
                <div class="text-xs text-muted-foreground">方法</div>
                <div>{{ detail.method || '-' }}</div>
              </div>
              <div>
                <div class="text-xs text-muted-foreground">域名</div>
                <div>{{ detail.host || '-' }}</div>
              </div>
              <div>
                <div class="text-xs text-muted-foreground">动作</div>
                <Badge
                  :class="isBlocked(detail) ? 'bg-destructive text-destructive-foreground' : 'bg-muted text-muted-foreground'"
                  class="border-transparent"
                >
                  {{ isBlocked(detail) ? '拦截' : '记录' }}
                </Badge>
              </div>
              <div class="col-span-2 md:col-span-3">
                <div class="text-xs text-muted-foreground">请求</div>
                <div class="break-all font-mono text-xs">{{ detail.method }} {{ detail.host }}{{ detail.uri }}</div>
              </div>
            </div>

            <!-- 命中规则 -->
            <div>
              <h3 class="mb-2 text-sm font-semibold">命中规则（{{ parsedRules.length }}）</h3>
              <div v-if="parsedRules.length" class="overflow-hidden rounded-lg border">
                <table class="w-full text-sm">
                  <thead class="bg-muted/60 text-xs text-muted-foreground">
                    <tr>
                      <th class="px-3 py-2 text-left">规则 ID</th>
                      <th class="px-3 py-2 text-left">类型</th>
                      <th class="px-3 py-2 text-left">级别</th>
                      <th class="px-3 py-2 text-left">描述</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="r in parsedRules" :key="r.id" class="border-t">
                      <td class="px-3 py-2 font-mono text-xs">{{ r.id }}</td>
                      <td class="px-3 py-2 text-xs">{{ groupMeta[r.group]?.label || r.group }}</td>
                      <td class="px-3 py-2">
                        <span
                          class="rounded px-1.5 py-0.5 text-[11px]"
                          :class="severityMeta[r.severity]?.cls || 'bg-muted text-muted-foreground'"
                        >
                          {{ severityMeta[r.severity]?.label || r.severity }}
                        </span>
                      </td>
                      <td class="px-3 py-2 text-xs">{{ r.msg }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <p v-else class="text-sm text-muted-foreground">无命中规则明细</p>
            </div>

            <!-- 请求头 -->
            <div v-if="parsedHeaders.length">
              <h3 class="mb-2 text-sm font-semibold">请求头（{{ parsedHeaders.length }}）</h3>
              <div class="overflow-hidden rounded-lg border">
                <table class="w-full text-sm">
                  <thead class="bg-muted/60 text-xs text-muted-foreground">
                    <tr>
                      <th class="px-3 py-2 text-left">名称</th>
                      <th class="px-3 py-2 text-left">值</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="(h, i) in parsedHeaders" :key="i" class="border-t">
                      <td class="px-3 py-1.5 font-mono text-xs">{{ h.name }}</td>
                      <td class="break-all px-3 py-1.5 font-mono text-xs text-muted-foreground">{{ h.value }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <!-- 请求体 -->
            <div v-if="detail.body">
              <h3 class="mb-2 text-sm font-semibold">请求体（前 8KB）</h3>
              <pre class="max-h-56 overflow-auto whitespace-pre-wrap rounded-lg border bg-muted/40 p-3 font-mono text-xs">{{ detail.body }}</pre>
            </div>
          </template>
        </div>
      </div>
    </div>
  </div>
</template>
