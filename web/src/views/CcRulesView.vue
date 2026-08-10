<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { api } from '@/api'
import type { CcRule } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
import { Plus, RefreshCw, ShieldAlert, Trash2 } from 'lucide-vue-next'

const rules = ref<CcRule[]>([])
const loading = ref(false)
const msg = ref('')
const error = ref('')
const editingId = ref<number | null>(null)

const emptyForm = () => ({
  name: '',
  host: '',
  path: '',
  rate: '100/60',
  ban_duration: 300,
  sort_order: 0,
  enabled: true,
})
const form = reactive(emptyForm())

async function load() {
  loading.value = true
  try {
    rules.value = await api.get<CcRule[]>('/cc-rules')
  } finally {
    loading.value = false
  }
}

function reset() {
  Object.assign(form, emptyForm())
  editingId.value = null
  error.value = ''
}

function edit(r: CcRule) {
  editingId.value = r.id
  Object.assign(form, {
    name: r.name,
    host: r.host,
    path: r.path,
    rate: r.rate,
    ban_duration: r.ban_duration,
    sort_order: r.sort_order,
    enabled: r.enabled,
  })
}

async function submit() {
  error.value = ''
  msg.value = ''
  const payload = { ...form }
  try {
    if (editingId.value) {
      await api.put(`/cc-rules/${editingId.value}`, payload)
      msg.value = '规则已更新'
    } else {
      await api.post('/cc-rules', payload)
      msg.value = '规则已创建'
    }
    reset()
    await load()
  } catch (e: any) {
    error.value = e.message || '保存失败'
  }
  setTimeout(() => (msg.value = ''), 3000)
}

async function toggle(r: CcRule) {
  await api.patch(`/cc-rules/${r.id}/enabled`, { enabled: !r.enabled })
  await load()
}

async function remove(r: CcRule) {
  if (!confirm(`确认删除规则「${r.name || '未命名'}」？`)) return
  await api.delete(`/cc-rules/${r.id}`)
  if (editingId.value === r.id) reset()
  await load()
}

async function publish() {
  msg.value = ''
  error.value = ''
  try {
    const d = await api.post<{ rule_count: number }>('/cc-rules/publish')
    msg.value = `已发布 ${d.rule_count} 条规则，引擎将在数秒内热更新生效`
  } catch (e: any) {
    error.value = e.message || '发布失败'
  }
  setTimeout(() => (msg.value = ''), 4000)
}

onMounted(load)
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-semibold flex items-center gap-2">
          <ShieldAlert class="h-6 w-6" /> CC 防刷
        </h1>
        <p class="text-sm text-muted-foreground">
          按域名与路径精细化配置访问频率，未命中规则的请求回退全局默认
        </p>
      </div>
      <Button :disabled="loading" @click="publish">发布并热更新</Button>
    </div>

    <div class="grid gap-4 lg:grid-cols-3">
      <!-- 规则表单 -->
      <Card class="h-fit lg:sticky lg:top-6">
        <CardHeader>
          <CardTitle class="text-base flex items-center gap-2">
            <Plus class="h-4 w-4" /> {{ editingId ? '编辑规则' : '新增规则' }}
          </CardTitle>
          <CardDescription>
            域名留空=所有；路径留空=所有（前缀匹配）；host+path 都填时优先命中
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-3">
          <div class="space-y-1.5">
            <Label>名称</Label>
            <Input v-model="form.name" placeholder="如 API 限流" />
          </div>
          <div class="space-y-1.5">
            <Label>域名 (Host)</Label>
            <Input v-model="form.host" placeholder="空=所有；支持 *.example.com" />
          </div>
          <div class="space-y-1.5">
            <Label>路径前缀</Label>
            <Input v-model="form.path" placeholder="空=所有；如 /api/v1" />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div class="space-y-1.5">
              <Label>频率（次/秒）</Label>
              <Input v-model="form.rate" placeholder="100/60" />
            </div>
            <div class="space-y-1.5">
              <Label>封禁时长（秒）</Label>
              <Input v-model.number="form.ban_duration" type="number" />
            </div>
          </div>
          <div class="grid grid-cols-2 gap-3 items-end">
            <div class="space-y-1.5">
              <Label>排序</Label>
              <Input v-model.number="form.sort_order" type="number" />
            </div>
            <label class="flex items-center gap-2 pb-2 text-sm">
              <input v-model="form.enabled" type="checkbox" class="h-4 w-4" /> 启用
            </label>
          </div>
          <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
          <p v-if="msg" class="text-sm text-primary">{{ msg }}</p>
          <div class="flex gap-2">
            <Button class="flex-1" @click="submit">{{ editingId ? '保存修改' : '添加规则' }}</Button>
            <Button v-if="editingId" variant="outline" @click="reset">取消</Button>
          </div>
        </CardContent>
      </Card>

      <!-- 规则列表 -->
      <Card class="lg:col-span-2">
        <CardContent class="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>名称</TableHead>
                <TableHead>域名</TableHead>
                <TableHead>路径</TableHead>
                <TableHead>频率</TableHead>
                <TableHead>封禁(秒)</TableHead>
                <TableHead>启用</TableHead>
                <TableHead class="text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow v-for="r in rules" :key="r.id">
                <TableCell class="font-medium">{{ r.name || '-' }}</TableCell>
                <TableCell class="font-mono text-xs">{{ r.host || '所有' }}</TableCell>
                <TableCell class="font-mono text-xs">{{ r.path || '所有' }}</TableCell>
                <TableCell class="font-mono text-xs">{{ r.rate }}</TableCell>
                <TableCell class="text-xs tabular-nums">{{ r.ban_duration }}</TableCell>
                <TableCell>
                  <Badge :variant="r.enabled ? 'success' : 'outline'">
                    {{ r.enabled ? '启用' : '停用' }}
                  </Badge>
                </TableCell>
                <TableCell class="text-right whitespace-nowrap">
                  <Button variant="ghost" size="sm" class="h-7 px-2 text-xs" @click="toggle(r)">
                    {{ r.enabled ? '停用' : '启用' }}
                  </Button>
                  <Button variant="ghost" size="sm" class="h-7 px-2 text-xs" @click="edit(r)">
                    编辑
                  </Button>
                  <Button variant="ghost" size="sm" class="h-7 px-2 text-xs text-destructive" @click="remove(r)">
                    <Trash2 class="h-3.5 w-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
              <TableRow v-if="rules.length === 0">
                <TableCell colspan="7" class="py-8 text-center text-muted-foreground">
                  暂无 CC 规则，默认回退全局频率（100/60）。
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
