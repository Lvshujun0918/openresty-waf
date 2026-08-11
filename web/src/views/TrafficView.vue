<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { api } from '@/api'
import type { PageResult, TrafficItem } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
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
import { Activity, Eraser } from 'lucide-vue-next'

const cfg = reactive<any>({ traffic_log: { enabled: false, retention_days: 7 } })
const items = ref<TrafficItem[]>([])
const total = ref(0)
const stats = ref({ total: 0, attack: 0 })
const page = ref(1)
const pageSize = ref(20)
const host = ref('')
const clientIp = ref('')
const attack = ref('')
const saving = ref(false)
const loading = ref(false)
const message = ref('')

async function loadCfg() {
  const d = await api.get<{ config: any }>('/config')
  Object.assign(cfg, d.config || {})
  cfg.traffic_log = cfg.traffic_log || {}
}

async function saveCfg() {
  saving.value = true
  message.value = ''
  try {
    await api.put('/config', { config: cfg })
    message.value = '全量记录配置已保存并下发，引擎将在数秒内热更新生效'
  } catch (e: any) {
    message.value = e.message || '保存失败'
  } finally {
    saving.value = false
  }
  setTimeout(() => (message.value = ''), 4000)
}

async function loadStats() {
  stats.value = await api.get<{ total: number; attack: number }>('/traffic/stats')
}

async function load() {
  loading.value = true
  const params = new URLSearchParams({
    page: String(page.value),
    page_size: String(pageSize.value),
  })
  if (host.value) params.set('host', host.value)
  if (clientIp.value) params.set('client_ip', clientIp.value)
  if (attack.value) params.set('attack', attack.value)
  const res = await api.get<PageResult<TrafficItem>>(`/traffic?${params}`)
  items.value = res.items
  total.value = res.total
  loading.value = false
}

async function cleanup() {
  const days = Number(cfg.traffic_log.retention_days) || 7
  try {
    const d = await api.post<{ deleted: number }>(`/traffic/cleanup?days=${days}`)
    message.value = `已清理 ${d.deleted} 条超过 ${days} 天的记录`
  } catch (e: any) {
    message.value = e.message || '清理失败'
  }
  await Promise.all([loadStats(), load()])
  setTimeout(() => (message.value = ''), 4000)
}

onMounted(async () => {
  await Promise.all([loadCfg(), loadStats(), load()])
})
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-semibold flex items-center gap-2">
          <Activity class="h-6 w-6" /> 流量日志
        </h1>
        <p class="text-sm text-muted-foreground">
          全量记录模式下记录每个请求；自动按保留天数清理过期数据
        </p>
      </div>
    </div>

    <p v-if="message" class="text-sm text-primary">{{ message }}</p>

    <!-- 配置开关 -->
    <Card>
      <CardHeader>
        <CardTitle class="text-base flex items-center gap-2">
          <Eraser class="h-4 w-4" /> 全量记录模式
        </CardTitle>
        <CardDescription>
          开启后引擎对每个请求上报一条记录（含是否命中攻击）；关闭则只记录攻击事件
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div class="flex flex-wrap items-end gap-6">
          <label class="flex items-center gap-2 text-sm">
            <input v-model="cfg.traffic_log.enabled" type="checkbox" class="h-4 w-4" />
            开启全量记录
          </label>
          <div class="space-y-1.5">
            <Label>保留天数（自动清理）</Label>
            <Input v-model.number="cfg.traffic_log.retention_days" type="number" min="1" class="w-32" />
          </div>
          <Button :disabled="saving" @click="saveCfg">{{ saving ? '保存中…' : '保存配置' }}</Button>
          <Button variant="outline" @click="cleanup">立即清理过期记录</Button>
        </div>
      </CardContent>
    </Card>

    <!-- 统计 + 过滤 -->
    <div class="grid gap-4 md:grid-cols-3">
      <Card>
        <CardHeader class="pb-2">
          <CardDescription>总记录数</CardDescription>
          <CardTitle class="text-2xl">{{ stats.total }}</CardTitle>
        </CardHeader>
      </Card>
      <Card>
        <CardHeader class="pb-2">
          <CardDescription>命中攻击</CardDescription>
          <CardTitle class="text-2xl text-destructive">{{ stats.attack }}</CardTitle>
        </CardHeader>
      </Card>
      <Card>
        <CardContent class="flex flex-wrap items-end gap-3 pt-6">
          <div class="space-y-1.5">
            <Label>域名</Label>
            <Input v-model="host" placeholder="如 example.com" class="w-40" />
          </div>
          <div class="space-y-1.5">
            <Label>IP</Label>
            <Input v-model="clientIp" placeholder="如 1.2.3.4" class="w-40" />
          </div>
          <div class="space-y-1.5">
            <Label>状态</Label>
            <select v-model="attack" class="h-9 rounded-md border border-input bg-transparent px-3 text-sm">
              <option value="">全部</option>
              <option value="1">仅攻击</option>
              <option value="0">非攻击</option>
            </select>
          </div>
          <Button @click="page = 1; load()">查询</Button>
        </CardContent>
      </Card>
    </div>

    <!-- 流量列表 -->
    <Card>
      <CardContent class="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>时间</TableHead>
              <TableHead>域名</TableHead>
              <TableHead>IP</TableHead>
              <TableHead>方法</TableHead>
              <TableHead>URI</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>攻击</TableHead>
              <TableHead>耗时(ms)</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="e in items" :key="e.id">
              <TableCell class="whitespace-nowrap text-xs text-muted-foreground">{{ e.time }}</TableCell>
              <TableCell class="max-w-[140px] truncate text-xs">{{ e.host || '-' }}</TableCell>
              <TableCell class="text-xs">
                <div class="font-mono">{{ e.client_ip }}</div>
                <div v-if="e.country" class="text-[11px] text-muted-foreground">{{ [e.country, e.province, e.city].filter(Boolean).join(' ') }}</div>
              </TableCell>
              <TableCell class="text-xs">{{ e.method }}</TableCell>
              <TableCell class="max-w-[220px] truncate font-mono text-xs" :title="e.uri">{{ e.uri }}</TableCell>
              <TableCell>
                <Badge :variant="e.status >= 400 ? 'destructive' : 'outline'">{{ e.status }}</Badge>
              </TableCell>
              <TableCell>
                <Badge v-if="e.attack" variant="destructive">攻击</Badge>
                <span v-else class="text-xs text-muted-foreground">正常</span>
              </TableCell>
              <TableCell class="text-xs tabular-nums">{{ Math.round(e.response_time) }}</TableCell>
            </TableRow>
            <TableRow v-if="items.length === 0">
              <TableCell colspan="8" class="py-8 text-center text-muted-foreground">
                暂无流量记录。开启「全量记录模式」后每个请求都会记录。
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </CardContent>
    </Card>

    <div class="flex items-center justify-between">
      <span class="text-sm text-muted-foreground">第 {{ page }} 页 / 共 {{ Math.ceil(total / pageSize) }} 页（{{ total }} 条）</span>
      <div class="flex gap-2">
        <Button variant="outline" size="sm" :disabled="page <= 1" @click="page--; load()">上一页</Button>
        <Button variant="outline" size="sm" :disabled="page * pageSize >= total" @click="page++; load()">下一页</Button>
      </div>
    </div>
  </div>
</template>
