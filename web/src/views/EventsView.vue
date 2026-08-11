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
const loading = ref(false)
const message = ref('')

async function load() {
  loading.value = true
  const params = new URLSearchParams({
    page: String(page.value),
    page_size: String(pageSize.value),
  })
  if (group.value) params.set('group', group.value)
  if (clientIp.value) params.set('client_ip', clientIp.value)
  if (host.value) params.set('host', host.value)
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
        <p class="text-sm text-muted-foreground">共 {{ total }} 条</p>
      </div>
      <Button variant="outline" @click="consume">消费 Redis 队列</Button>
    </div>

    <Card>
      <CardHeader>
        <CardTitle>过滤</CardTitle>
      </CardHeader>
      <CardContent class="flex flex-wrap items-end gap-4">
        <div class="space-y-1.5">
          <Label>攻击类型</Label>
          <select v-model="group" class="h-9 rounded-md border border-input bg-transparent px-3 text-sm">
            <option value="">全部</option>
            <option v-for="g in ['sqli','xss','rce','lfi','ssrf','protocol','leak','scanner','custom']" :key="g" :value="g">{{ g }}</option>
          </select>
        </div>
        <div class="space-y-1.5">
          <Label>客户端 IP</Label>
          <Input v-model="clientIp" placeholder="如 192.168.1.1" class="w-48" />
        </div>
        <div class="space-y-1.5">
          <Label>域名 (Host)</Label>
          <Input v-model="host" placeholder="如 example.com" class="w-48" />
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
              <TableHead>域名</TableHead>
              <TableHead>IP</TableHead>
              <TableHead>方法</TableHead>
              <TableHead>URI</TableHead>
              <TableHead>类型</TableHead>
              <TableHead>规则</TableHead>
              <TableHead>消息</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="e in events" :key="e.id">
              <TableCell class="whitespace-nowrap text-xs">{{ e.time }}</TableCell>
              <TableCell class="max-w-[140px] truncate text-xs">{{ e.host || '-' }}</TableCell>
              <TableCell class="text-xs">
                <div class="font-mono">{{ e.client_ip }}</div>
                <div v-if="e.country" class="text-[11px] text-muted-foreground">{{ [e.country, e.province, e.city].filter(Boolean).join(' ') }}</div>
              </TableCell>
              <TableCell class="text-xs">{{ e.method }}</TableCell>
              <TableCell class="max-w-[200px] truncate font-mono text-xs">{{ e.uri }}</TableCell>
              <TableCell><Badge variant="destructive">{{ e.group }}</Badge></TableCell>
              <TableCell class="font-mono text-xs">{{ e.rule_id }}</TableCell>
              <TableCell class="max-w-[240px] truncate text-xs">{{ e.msg }}</TableCell>
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
