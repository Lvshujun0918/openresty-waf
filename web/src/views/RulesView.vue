<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api } from '@/api'
import type { Rule } from '@/types'
import { RULE_GROUPS } from '@/types'
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

const rules = ref<Rule[]>([])
const loading = ref(false)
const message = ref('')
const editing = ref<Rule | null>(null)
const showForm = ref(false)

// 表单状态
const form = ref({
  id: 0,
  rule_id: '',
  name: '',
  group: 'custom',
  severity: 2,
  enabled: true,
  operator: 'REGEX',
  pattern: '',
  transforms: '["url_decode","to_lowercase"]',
  vars: '[{"type":"URI_ARGS"},{"type":"POST_ARGS"},{"type":"BODY"}]',
  status: 403,
  message: '',
})

async function load() {
  loading.value = true
  rules.value = await api.get<Rule[]>('/rules')
  loading.value = false
}

function startCreate() {
  editing.value = null
  form.value = {
    id: 0, rule_id: '', name: '', group: 'custom', severity: 2, enabled: true,
    operator: 'REGEX', pattern: '', transforms: '["url_decode","to_lowercase"]',
    vars: '[{"type":"URI_ARGS"},{"type":"POST_ARGS"},{"type":"BODY"}]',
    status: 403, message: '',
  }
  showForm.value = true
}

function startEdit(r: Rule) {
  editing.value = r
  form.value = {
    id: r.id, rule_id: r.rule_id, name: r.name, group: r.group, severity: r.severity,
    enabled: r.enabled, operator: r.operator, pattern: r.pattern,
    transforms: r.transforms, vars: r.vars, status: r.status, message: r.message,
  }
  showForm.value = true
}

async function save() {
  if (!form.value.rule_id || !form.value.pattern) {
    message.value = 'rule_id 与 pattern 不能为空'
    return
  }
  // 校验 JSON
  try {
    JSON.parse(form.value.transforms)
    JSON.parse(form.value.vars)
  } catch {
    message.value = 'transforms / vars 需为合法 JSON'
    return
  }
  const payload = { ...form.value }
  const actions = JSON.stringify({ disrupt: 'BLOCK', status: form.value.status, msg: form.value.message })
  if (editing.value) {
    await api.put(`/rules/${editing.value.id}`, { ...payload, actions })
  } else {
    await api.post('/rules', { ...payload, actions })
  }
  showForm.value = false
  message.value = '已保存（需点击"发布规则"生效）'
  await load()
  setTimeout(() => (message.value = ''), 3000)
}

async function toggle(r: Rule) {
  await api.patch(`/rules/${r.id}/enabled`, { enabled: !r.enabled })
  await load()
}

async function remove(r: Rule) {
  if (!confirm(`确认删除规则 ${r.rule_id}？`)) return
  await api.delete(`/rules/${r.id}`)
  await load()
}

async function publish() {
  const res = await api.post<{ version: string; rule_count: number }>('/rules/publish')
  message.value = `已发布 ${res.rule_count} 条规则（版本 ${res.version}）`
  setTimeout(() => (message.value = ''), 4000)
}

onMounted(load)
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-semibold">规则管理</h1>
        <p class="text-sm text-muted-foreground">共 {{ rules.length }} 条规则</p>
      </div>
      <div class="flex gap-2">
        <Button variant="outline" @click="publish">发布规则</Button>
        <Button @click="startCreate">新增规则</Button>
      </div>
    </div>

    <p v-if="message" class="text-sm text-muted-foreground">{{ message }}</p>

    <!-- 新增/编辑表单 -->
    <Card v-if="showForm" class="border-primary/40">
      <CardHeader>
        <CardTitle>{{ editing ? '编辑规则' : '新增规则' }}</CardTitle>
        <CardDescription>规则字段与 Lua 引擎 DSL 对应，保存后需发布生效</CardDescription>
      </CardHeader>
      <CardContent>
        <div class="grid gap-4 md:grid-cols-2">
          <div class="space-y-1.5">
            <Label>规则 ID</Label>
            <Input v-model="form.rule_id" placeholder="如 30001" />
          </div>
          <div class="space-y-1.5">
            <Label>规则名称</Label>
            <Input v-model="form.name" placeholder="如 自定义 UA 拦截" />
          </div>
          <div class="space-y-1.5">
            <Label>分组</Label>
            <select v-model="form.group" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
              <option v-for="g in RULE_GROUPS" :key="g" :value="g">{{ g }}</option>
            </select>
          </div>
          <div class="space-y-1.5">
            <Label>运算符</Label>
            <select v-model="form.operator" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
              <option value="REGEX">REGEX</option>
              <option value="CIDR">CIDR</option>
              <option value="PM">PM</option>
              <option value="EQUALS">EQUALS</option>
              <option value="CONTAINS">CONTAINS</option>
              <option value="STARTS_WITH">STARTS_WITH</option>
              <option value="ENDS_WITH">ENDS_WITH</option>
            </select>
          </div>
          <div class="space-y-1.5 md:col-span-2">
            <Label>匹配模式（正则 / 值）</Label>
            <textarea
              v-model="form.pattern"
              rows="3"
              class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-sm"
              placeholder="如 \b(sleep|benchmark)\s*\("
            />
          </div>
          <div class="space-y-1.5">
            <Label>拦截状态码</Label>
            <Input v-model.number="form.status" type="number" />
          </div>
          <div class="space-y-1.5">
            <Label>提示消息</Label>
            <Input v-model="form.message" placeholder="命中后的日志消息" />
          </div>
          <div class="space-y-1.5">
            <Label>严重级别</Label>
            <select v-model.number="form.severity" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
              <option :value="1">1 - 低</option>
              <option :value="2">2 - 中</option>
              <option :value="3">3 - 高</option>
            </select>
          </div>
          <div class="flex items-end gap-2">
            <label class="flex items-center gap-2 text-sm">
              <input v-model="form.enabled" type="checkbox" class="h-4 w-4" />
              启用
            </label>
          </div>
          <div class="space-y-1.5">
            <Label>变量（JSON）</Label>
            <textarea v-model="form.vars" rows="2" class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs" />
          </div>
          <div class="space-y-1.5">
            <Label>变换（JSON）</Label>
            <textarea v-model="form.transforms" rows="2" class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs" />
          </div>
        </div>
        <div class="mt-4 flex gap-2">
          <Button @click="save">保存</Button>
          <Button variant="outline" @click="showForm = false">取消</Button>
        </div>
      </CardContent>
    </Card>

    <!-- 规则表格 -->
    <Card>
      <CardContent class="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>ID</TableHead>
              <TableHead>名称</TableHead>
              <TableHead>分组</TableHead>
              <TableHead>运算符</TableHead>
              <TableHead>状态</TableHead>
              <TableHead class="w-40">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="r in rules" :key="r.id">
              <TableCell class="font-mono text-xs">{{ r.rule_id }}</TableCell>
              <TableCell class="text-sm">{{ r.name }}</TableCell>
              <TableCell><Badge variant="secondary">{{ r.group }}</Badge></TableCell>
              <TableCell class="font-mono text-xs">{{ r.operator }}</TableCell>
              <TableCell>
                <Badge :variant="r.enabled ? 'default' : 'outline'">
                  {{ r.enabled ? '启用' : '禁用' }}
                </Badge>
              </TableCell>
              <TableCell>
                <div class="flex gap-1">
                  <Button variant="ghost" size="sm" @click="toggle(r)">
                    {{ r.enabled ? '禁用' : '启用' }}
                  </Button>
                  <Button variant="ghost" size="sm" @click="startEdit(r)">编辑</Button>
                  <Button variant="ghost" size="sm" class="text-destructive" @click="remove(r)">
                    删除
                  </Button>
                </div>
              </TableCell>
            </TableRow>
            <TableRow v-if="rules.length === 0">
              <TableCell colspan="6" class="py-8 text-center text-muted-foreground">
                暂无规则，点击"新增规则"
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  </div>
</template>
