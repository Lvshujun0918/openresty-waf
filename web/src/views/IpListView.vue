<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { api } from '@/api'
import type { IpListSub } from '@/types'
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
import { Ban, Plus, RefreshCw, Save, Trash2 } from 'lucide-vue-next'

// ---- 手动名单 ----
const cfg = reactive<any>({})
const wlIps = ref('')
const blIps = ref('')
const wlUrls = ref('')
const blUrls = ref('')
const wlUa = ref('')

// ---- 远程订阅 ----
const subs = ref<IpListSub[]>([])
const editingSubId = ref<number | null>(null)
const subForm = reactive({ name: '', url: '', type: 'blacklist', interval_min: 60 })

const loading = ref(false)
const msg = ref('')
const error = ref('')

function toList(s: string): string[] {
  return s
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
}
function toStr(arr: unknown[] | undefined): string {
  return (arr || []).join(', ')
}

async function loadManual() {
  const d = await api.get<{ config: any }>('/config')
  Object.assign(cfg, d.config || {})
  cfg.whitelist = cfg.whitelist || {}
  cfg.blacklist = cfg.blacklist || {}
  wlIps.value = toStr(cfg.whitelist.ips)
  wlUrls.value = toStr(cfg.whitelist.urls)
  wlUa.value = toStr(cfg.whitelist.user_agents)
  blIps.value = toStr(cfg.blacklist.ips)
  blUrls.value = toStr(cfg.blacklist.urls)
}

async function saveManual() {
  msg.value = ''
  error.value = ''
  try {
    cfg.whitelist.ips = toList(wlIps.value)
    cfg.whitelist.urls = toList(wlUrls.value)
    cfg.whitelist.user_agents = toList(wlUa.value)
    cfg.blacklist.ips = toList(blIps.value)
    cfg.blacklist.urls = toList(blUrls.value)
    await api.put('/config', { config: cfg })
    msg.value = '名单已保存并下发，引擎将在数秒内热更新生效'
  } catch (e: any) {
    error.value = e.message || '保存失败'
  }
  setTimeout(() => (msg.value = ''), 4000)
}

async function loadSubs() {
  subs.value = await api.get<IpListSub[]>('/ip-list-subs')
}

function resetSubForm() {
  editingSubId.value = null
  Object.assign(subForm, { name: '', url: '', type: 'blacklist', interval_min: 60 })
}

function editSub(s: IpListSub) {
  editingSubId.value = s.id
  Object.assign(subForm, {
    name: s.name,
    url: s.url,
    type: s.type,
    interval_min: s.interval_min,
  })
}

async function saveSub() {
  error.value = ''
  try {
    if (editingSubId.value) {
      await api.put(`/ip-list-subs/${editingSubId.value}`, { ...subForm })
    } else {
      await api.post('/ip-list-subs', { ...subForm })
    }
    resetSubForm()
    await loadSubs()
  } catch (e: any) {
    error.value = e.message || '保存订阅失败'
  }
}

async function delSub(s: IpListSub) {
  if (!confirm(`确认删除订阅「${s.name}」？`)) return
  await api.delete(`/ip-list-subs/${s.id}`)
  if (editingSubId.value === s.id) resetSubForm()
  await loadSubs()
}

async function toggleSub(s: IpListSub) {
  await api.patch(`/ip-list-subs/${s.id}/enabled`, { enabled: !s.enabled })
  await loadSubs()
}

async function syncSub(s: IpListSub) {
  msg.value = ''
  try {
    const d = await api.post<{ imported: number }>(`/ip-list-subs/${s.id}/sync`)
    msg.value = `「${s.name}」同步完成，并入 ${d.imported} 条`
  } catch (e: any) {
    error.value = e.message || '同步失败'
  }
  await loadSubs()
  setTimeout(() => (msg.value = ''), 4000)
}

onMounted(async () => {
  loading.value = true
  try {
    await Promise.all([loadManual(), loadSubs()])
  } catch (e: any) {
    error.value = e.message || '加载失败'
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="space-y-4">
    <div>
      <h1 class="text-2xl font-semibold flex items-center gap-2">
        <Ban class="h-6 w-6" /> IP 黑白名单
      </h1>
      <p class="text-sm text-muted-foreground">
        手动维护 IP/URL/UA 名单，并可订阅远程威胁情报 IP 列表（定时自动同步）
      </p>
    </div>

    <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
    <p v-if="msg" class="text-sm text-primary">{{ msg }}</p>

    <!-- 手动名单 -->
    <Card>
      <CardHeader>
        <CardTitle class="text-base flex items-center gap-2">
          <Save class="h-4 w-4" /> 手动名单
        </CardTitle>
        <CardDescription>每行或逗号分隔多个条目，支持 IP / CIDR / URL 正则</CardDescription>
      </CardHeader>
      <CardContent>
        <div class="grid gap-4 md:grid-cols-2">
          <div class="space-y-1.5">
            <Label>白名单 IP（支持 CIDR）</Label>
            <textarea v-model="wlIps" rows="4" class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs" placeholder="127.0.0.1, 10.0.0.0/8" />
          </div>
          <div class="space-y-1.5">
            <Label>黑名单 IP（支持 CIDR）</Label>
            <textarea v-model="blIps" rows="4" class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs" placeholder="1.2.3.4" />
          </div>
          <div class="space-y-1.5">
            <Label>白名单 URL（正则）</Label>
            <textarea v-model="wlUrls" rows="2" class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs" />
          </div>
          <div class="space-y-1.5">
            <Label>黑名单 URL（正则）</Label>
            <textarea v-model="blUrls" rows="2" class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs" />
          </div>
          <div class="space-y-1.5 md:col-span-2">
            <Label>白名单 UA（正则）</Label>
            <textarea v-model="wlUa" rows="2" class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs" />
          </div>
        </div>
        <Button class="mt-4" @click="saveManual">保存并下发</Button>
      </CardContent>
    </Card>

    <!-- 远程订阅 -->
    <Card>
      <CardHeader>
        <CardTitle class="text-base flex items-center gap-2">
          <RefreshCw class="h-4 w-4" /> 远程订阅
        </CardTitle>
        <CardDescription>
          定时拉取远程 IP 列表并合并到对应名单（支持威胁情报源，如防火墙封禁列表）；后台每分钟检查到期订阅
        </CardDescription>
      </CardHeader>
      <CardContent class="space-y-4">
        <!-- 订阅表单 -->
        <div class="grid gap-3 md:grid-cols-6 items-end rounded-lg border border-border/60 p-3">
          <div class="md:col-span-2 space-y-1.5">
            <Label>名称</Label>
            <Input v-model="subForm.name" placeholder="如 威胁情报源" />
          </div>
          <div class="md:col-span-2 space-y-1.5">
            <Label>URL</Label>
            <Input v-model="subForm.url" placeholder="https://example.com/ips.txt" />
          </div>
          <div class="space-y-1.5">
            <Label>类型</Label>
            <select v-model="subForm.type" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
              <option value="blacklist">黑名单</option>
              <option value="whitelist">白名单</option>
            </select>
          </div>
          <div class="space-y-1.5">
            <Label>周期（分钟）</Label>
            <Input v-model.number="subForm.interval_min" type="number" min="1" />
          </div>
          <div class="md:col-span-6 flex gap-2">
            <Button size="sm" @click="saveSub">
              <Plus class="h-4 w-4" /> {{ editingSubId ? '保存修改' : '添加订阅' }}
            </Button>
            <Button v-if="editingSubId" size="sm" variant="outline" @click="resetSubForm">取消</Button>
          </div>
        </div>

        <!-- 订阅列表 -->
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>名称</TableHead>
              <TableHead>URL</TableHead>
              <TableHead>类型</TableHead>
              <TableHead>周期</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>数量</TableHead>
              <TableHead>启用</TableHead>
              <TableHead class="text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="s in subs" :key="s.id">
              <TableCell class="font-medium">{{ s.name }}</TableCell>
              <TableCell class="max-w-[180px] truncate font-mono text-xs">{{ s.url }}</TableCell>
              <TableCell>
                <Badge :variant="s.type === 'blacklist' ? 'destructive' : 'success'">
                  {{ s.type === 'blacklist' ? '黑名单' : '白名单' }}
                </Badge>
              </TableCell>
              <TableCell class="text-xs tabular-nums">{{ s.interval_min }}m</TableCell>
              <TableCell class="max-w-[140px] truncate text-xs">
                <span :class="s.last_status === 'ok' ? 'text-success' : 'text-destructive'">
                  {{ s.last_status || '未同步' }}
                </span>
              </TableCell>
              <TableCell class="text-xs tabular-nums">{{ s.last_count ?? '-' }}</TableCell>
              <TableCell>
                <Badge :variant="s.enabled ? 'default' : 'outline'">
                  {{ s.enabled ? '启用' : '停用' }}
                </Badge>
              </TableCell>
              <TableCell class="text-right whitespace-nowrap">
                <Button variant="ghost" size="sm" class="h-7 px-2 text-xs" @click="syncSub(s)">
                  同步
                </Button>
                <Button variant="ghost" size="sm" class="h-7 px-2 text-xs" @click="toggleSub(s)">
                  {{ s.enabled ? '停用' : '启用' }}
                </Button>
                <Button variant="ghost" size="sm" class="h-7 px-2 text-xs" @click="editSub(s)">
                  编辑
                </Button>
                <Button variant="ghost" size="sm" class="h-7 px-2 text-xs text-destructive" @click="delSub(s)">
                  <Trash2 class="h-3.5 w-3.5" />
                </Button>
              </TableCell>
            </TableRow>
            <TableRow v-if="subs.length === 0">
              <TableCell colspan="8" class="py-6 text-center text-muted-foreground">
                暂无订阅源，可添加远程 IP 列表自动同步
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  </div>
</template>
