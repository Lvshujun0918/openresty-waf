<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api } from '@/api'
import type { EventItem, Rule } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

const ruleCount = ref(0)
const enabledCount = ref(0)
const eventTotal = ref(0)
const recentEvents = ref<EventItem[]>([])
const groupCounts = ref<Record<string, number>>({})
const groups = ['sqli', 'xss', 'rce', 'lfi', 'ssrf', 'protocol', 'leak', 'scanner']

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
}

onMounted(load)
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-semibold">仪表盘</h1>
      <p class="text-sm text-muted-foreground">WAF 运行概览</p>
    </div>

    <div class="grid gap-4 md:grid-cols-3">
      <Card>
        <CardHeader>
          <CardDescription>拦截规则总数</CardDescription>
          <CardTitle class="text-3xl">{{ ruleCount }}</CardTitle>
        </CardHeader>
      </Card>
      <Card>
        <CardHeader>
          <CardDescription>启用规则</CardDescription>
          <CardTitle class="text-3xl">{{ enabledCount }}</CardTitle>
        </CardHeader>
      </Card>
      <Card>
        <CardHeader>
          <CardDescription>攻击事件累计</CardDescription>
          <CardTitle class="text-3xl">{{ eventTotal }}</CardTitle>
        </CardHeader>
      </Card>
    </div>

    <div class="grid gap-4 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>攻击类型分布</CardTitle>
        </CardHeader>
        <CardContent class="space-y-2">
          <div
            v-for="g in groups"
            :key="g"
            class="flex items-center justify-between rounded-md border px-3 py-2"
          >
            <Badge variant="secondary">{{ g }}</Badge>
            <span class="text-lg font-semibold">{{ groupCounts[g] ?? 0 }}</span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>近期攻击事件</CardTitle>
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
                <TableCell class="whitespace-nowrap text-xs">{{ e.time }}</TableCell>
                <TableCell class="font-mono text-xs">{{ e.client_ip }}</TableCell>
                <TableCell><Badge variant="destructive">{{ e.group }}</Badge></TableCell>
                <TableCell class="font-mono text-xs">{{ e.rule_id }}</TableCell>
              </TableRow>
              <TableRow v-if="recentEvents.length === 0">
                <TableCell colspan="4" class="text-center text-muted-foreground">暂无事件</TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
