<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { api } from '@/api'
import type { Rule } from '@/types'
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

// ---------- 友好选项 ----------
const GROUP_OPTIONS = [
  ['sqli', 'SQL 注入'], ['xss', 'XSS 跨站'], ['rce', '远程执行'], ['lfi', '文件包含'],
  ['ssrf', 'SSRF'], ['protocol', '协议异常'], ['leak', '信息泄露'], ['scanner', '扫描器'],
  ['custom', '自定义'],
] as const

const TARGET_OPTIONS = [
  ['URI', 'URL 路径'], ['REQUEST_URI', '完整 URI'], ['URI_ARGS', 'GET 参数'],
  ['POST_ARGS', 'POST 参数'], ['HEADERS', '请求头'], ['COOKIE', 'Cookie'],
  ['BODY', '请求体'], ['METHOD', '请求方法'],
] as const

const MATCH_OPTIONS = [
  ['CONTAINS', '包含文本'], ['REGEX', '正则匹配'], ['EQUALS', '完全等于'],
  ['STARTS_WITH', '以…开头'], ['ENDS_WITH', '以…结尾'], ['PM', '词语命中(任一)'],
  ['CIDR', 'IP 网段'], ['EXISTS', '存在即可'],
  ['LIBINJECTION_SQLI', 'SQL 注入语义检测'], ['LIBINJECTION_XSS', 'XSS 语义检测'],
] as const

const TRANSFORM_OPTIONS = [
  ['url_decode', 'URL 解码'], ['to_lowercase', '转小写'],
  ['remove_comments', '去除 SQL 注释'], ['compress_whitespace', '压缩空白'],
  ['normalize_path', '规范化路径'],
] as const

const ACTION_OPTIONS = [
  ['BLOCK', '拦截（返回状态码）'], ['LOG_ONLY', '仅记录不拦截'], ['ACCEPT', '放行跳过后续'],
] as const

// ---------- DSL 双向转换 ----------
function targetsToVars(targets: string[], specific: string, includeKeys: boolean): string {
  const vars: any[] = []
  const parse = includeKeys ? ['keys'] : undefined
  for (const t of targets) {
    const v: any = { type: t }
    if (specific && (t === 'HEADERS' || t === 'COOKIE' || t === 'URI_ARGS' || t === 'POST_ARGS')) {
      v.specific = specific
    }
    if (parse) v.parse = parse
    vars.push(v)
  }
  return JSON.stringify(vars)
}

function varsToTargets(varsStr: string): { targets: string[]; specific: string; includeKeys: boolean } {
  let vars: any[] = []
  try {
    vars = JSON.parse(varsStr || '[]')
  } catch {
    vars = []
  }
  const targets: string[] = []
  let specific = ''
  let includeKeys = false
  for (const v of vars) {
    if (v && typeof v.type === 'string' && !targets.includes(v.type)) targets.push(v.type)
    if (v?.specific) specific = v.specific
    if (v?.parse?.includes('keys')) includeKeys = true
  }
  return { targets, specific, includeKeys }
}

// ---------- 状态 ----------
const rules = ref<Rule[]>([])
const loading = ref(false)
const message = ref('')
const editing = ref<Rule | null>(null)
const showForm = ref(false)

const form = reactive({
  id: 0,
  rule_id: '',
  name: '',
  group: 'custom',
  severity: 2,
  enabled: true,
  matchType: 'CONTAINS',
  pattern: '',
  targets: ['URI_ARGS', 'POST_ARGS', 'BODY'] as string[],
  specific: '',
  includeKeys: false,
  transforms: ['url_decode', 'to_lowercase'] as string[],
  action: 'BLOCK',
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
  Object.assign(form, {
    id: 0, rule_id: '', name: '', group: 'custom', severity: 2, enabled: true,
    matchType: 'CONTAINS', pattern: '', targets: ['URI_ARGS', 'POST_ARGS', 'BODY'],
    specific: '', includeKeys: false, transforms: ['url_decode', 'to_lowercase'],
    action: 'BLOCK', status: 403, message: '',
  })
  showForm.value = true
}

function startEdit(r: Rule) {
  editing.value = r
  const vt = varsToTargets(r.vars)
  let transforms: string[] = []
  try {
    transforms = JSON.parse(r.transforms || '[]')
  } catch {
    transforms = []
  }
  Object.assign(form, {
    id: r.id, rule_id: r.rule_id, name: r.name, group: r.group, severity: r.severity,
    enabled: r.enabled, matchType: r.operator, pattern: r.pattern,
    targets: vt.targets.length ? vt.targets : ['URI_ARGS'],
    specific: vt.specific, includeKeys: vt.includeKeys, transforms,
    action: 'BLOCK', status: r.status, message: r.message,
  })
  showForm.value = true
}

async function save() {
  message.value = ''
  if (form.targets.length === 0) {
    message.value = '请至少选择一个检测目标'
    return
  }
  if (form.matchType !== 'LIBINJECTION_SQLI' && form.matchType !== 'LIBINJECTION_XSS' && !form.pattern) {
    message.value = '请输入匹配值'
    return
  }
  if (!form.name) form.name = form.pattern.slice(0, 40) || '自定义规则'
  if (!form.rule_id) form.rule_id = '9' + String(Date.now()).slice(-5)

  const payload: any = {
    rule_id: form.rule_id,
    name: form.name,
    group: form.group,
    severity: Number(form.severity),
    enabled: form.enabled,
    operator: form.matchType,
    pattern: form.pattern,
    transforms: JSON.stringify(form.transforms),
    vars: targetsToVars(form.targets, form.specific, form.includeKeys),
    status: Number(form.status),
    message: form.message,
    actions: JSON.stringify({
      disrupt: form.action,
      status: Number(form.status),
      msg: form.message,
    }),
  }
  if (editing.value) {
    await api.put(`/rules/${editing.value.id}`, payload)
  } else {
    await api.post('/rules', payload)
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

// ---------- 规则测试 ----------
const testRuleID = ref('')
const testURI = ref('/')
const testMethod = ref('GET')
const testBody = ref('')
const testContentType = ref('application/x-www-form-urlencoded')
const testResult = ref('')
const testNote = ref('')
const testing = ref(false)

async function runTest() {
  if (!testRuleID.value) {
    testResult.value = '请先选择规则'
    return
  }
  testing.value = true
  testResult.value = ''
  testNote.value = ''
  try {
    const d = await api.post<{ matched: boolean; note?: string }>('/rules/test', {
      rule_id: testRuleID.value,
      request: {
        method: testMethod.value,
        uri: testURI.value,
        body: testBody.value,
        content_type: testContentType.value,
      },
    })
    testResult.value = d.matched ? '✅ 命中（会触发该规则）' : '❌ 未命中'
    if (d.note) testNote.value = d.note
  } catch (e: any) {
    testResult.value = '测试失败: ' + (e.message || '')
  } finally {
    testing.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-semibold">规则管理</h1>
        <p class="text-sm text-muted-foreground">共 {{ rules.length }} 条规则（内置 + 自定义），改后需发布生效</p>
      </div>
      <div class="flex gap-2">
        <Button variant="outline" @click="publish">发布规则</Button>
        <Button @click="startCreate">新增规则</Button>
      </div>
    </div>

    <p v-if="message" class="text-sm text-muted-foreground">{{ message }}</p>

    <!-- 规则测试 -->
    <Card>
      <CardHeader>
        <CardTitle>规则测试</CardTitle>
        <CardDescription>用模拟请求验证规则是否命中（保存/发布前先测），libinjection 语义规则需在引擎真实流量验证</CardDescription>
      </CardHeader>
      <CardContent class="grid gap-4 md:grid-cols-2">
        <div class="space-y-1.5">
          <Label>选择规则</Label>
          <select v-model="testRuleID" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
            <option value="">— 选择规则 —</option>
            <option v-for="r in rules" :key="r.id" :value="r.rule_id">{{ r.rule_id }} · {{ r.name }}</option>
          </select>
        </div>
        <div class="space-y-1.5">
          <Label>方法</Label>
          <select v-model="testMethod" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
            <option>GET</option>
            <option>POST</option>
            <option>PUT</option>
            <option>DELETE</option>
          </select>
        </div>
        <div class="space-y-1.5 md:col-span-2">
          <Label>URI</Label>
          <Input v-model="testURI" placeholder="/index.php?id=1 union select 2" />
        </div>
        <div class="space-y-1.5">
          <Label>Content-Type</Label>
          <select v-model="testContentType" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
            <option>application/x-www-form-urlencoded</option>
            <option>application/json</option>
            <option>text/plain</option>
          </select>
        </div>
        <div class="space-y-1.5">
          <Label>请求体</Label>
          <Input v-model="testBody" placeholder="POST body" />
        </div>
        <div class="md:col-span-2 flex flex-wrap items-center gap-3">
          <Button :disabled="testing" @click="runTest">{{ testing ? '测试中…' : '测试' }}</Button>
          <span v-if="testResult" class="text-sm font-medium" :class="testResult.includes('命中') ? 'text-destructive' : 'text-muted-foreground'">{{ testResult }}</span>
          <span v-if="testNote" class="text-xs text-muted-foreground">{{ testNote }}</span>
        </div>
      </CardContent>
    </Card>

    <!-- 新增/编辑表单（友好式） -->
    <Card v-if="showForm" class="border-primary/40">
      <CardHeader>
        <CardTitle>{{ editing ? '编辑规则' : '新增自定义规则' }}</CardTitle>
        <CardDescription>
          用白话配置即可，无需了解 Lua DSL；语义检测（SQLi/XSS）依赖 libinjection 组件
        </CardDescription>
      </CardHeader>
      <CardContent class="space-y-5">
        <div class="grid gap-4 md:grid-cols-3">
          <div class="space-y-1.5">
            <Label>规则名称</Label>
            <Input v-model="form.name" placeholder="如 拦截 /admin 暴力枚举" />
          </div>
          <div class="space-y-1.5">
            <Label>攻击类型</Label>
            <select v-model="form.group" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
              <option v-for="[k, label] in GROUP_OPTIONS" :key="k" :value="k">{{ label }}</option>
            </select>
          </div>
          <div class="space-y-1.5">
            <Label>严重级别</Label>
            <select v-model.number="form.severity" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
              <option :value="1">1 - 低</option>
              <option :value="2">2 - 中</option>
              <option :value="3">3 - 高</option>
            </select>
          </div>
        </div>

        <!-- 检测目标 -->
        <div class="space-y-2">
          <Label>检测目标（对哪些内容检查）</Label>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-2">
            <label
              v-for="[k, label] in TARGET_OPTIONS"
              :key="k"
              class="flex items-center gap-2 rounded-md border border-border/60 px-3 py-2 text-sm cursor-pointer"
            >
              <input v-model="form.targets" type="checkbox" :value="k" class="h-4 w-4" />
              {{ label }}
            </label>
          </div>
          <div class="flex flex-wrap items-end gap-4">
            <div class="space-y-1.5">
              <Label>指定字段（可选，如 user-agent / session）</Label>
              <Input v-model="form.specific" placeholder="留空=全部" class="w-64" />
            </div>
            <label class="flex items-center gap-2 pb-2 text-sm">
              <input v-model="form.includeKeys" type="checkbox" class="h-4 w-4" />
              同时检查参数名（键）
            </label>
          </div>
        </div>

        <!-- 匹配方式 -->
        <div class="grid gap-4 md:grid-cols-4">
          <div class="space-y-1.5">
            <Label>匹配方式</Label>
            <select v-model="form.matchType" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
              <option v-for="[k, label] in MATCH_OPTIONS" :key="k" :value="k">{{ label }}</option>
            </select>
          </div>
          <div class="space-y-1.5 md:col-span-3">
            <Label>匹配值</Label>
            <textarea
              v-model="form.pattern"
              rows="2"
              class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-sm"
              placeholder="包含文本 / 正则 / IP 段，如：admin/login"
              :disabled="form.matchType === 'LIBINJECTION_SQLI' || form.matchType === 'LIBINJECTION_XSS' || form.matchType === 'EXISTS'"
            />
          </div>
        </div>

        <!-- 预处理 -->
        <div class="space-y-2">
          <Label>预处理（防绕过，可多选）</Label>
          <div class="flex flex-wrap gap-2">
            <label
              v-for="[k, label] in TRANSFORM_OPTIONS"
              :key="k"
              class="flex items-center gap-2 rounded-md border border-border/60 px-3 py-1.5 text-sm cursor-pointer"
            >
              <input v-model="form.transforms" type="checkbox" :value="k" class="h-4 w-4" />
              {{ label }}
            </label>
          </div>
        </div>

        <!-- 动作 -->
        <div class="grid gap-4 md:grid-cols-3">
          <div class="space-y-1.5">
            <Label>命中动作</Label>
            <select v-model="form.action" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
              <option v-for="[k, label] in ACTION_OPTIONS" :key="k" :value="k">{{ label }}</option>
            </select>
          </div>
          <div class="space-y-1.5" v-if="form.action === 'BLOCK'">
            <Label>状态码</Label>
            <Input v-model.number="form.status" type="number" />
          </div>
          <div class="space-y-1.5 md:col-span-2">
            <Label>提示消息（命中后记录）</Label>
            <Input v-model="form.message" placeholder="如 检测到恶意请求" />
          </div>
        </div>

        <div class="flex items-center gap-4">
          <label class="flex items-center gap-2 text-sm">
            <input v-model="form.enabled" type="checkbox" class="h-4 w-4" />
            启用
          </label>
          <div class="ml-auto flex gap-2">
            <Button @click="save">保存规则</Button>
            <Button variant="outline" @click="showForm = false">取消</Button>
          </div>
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
              <TableHead>匹配</TableHead>
              <TableHead>状态</TableHead>
              <TableHead class="w-40">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="r in rules" :key="r.id">
              <TableCell class="font-mono text-xs">{{ r.rule_id }}</TableCell>
              <TableCell class="max-w-[240px] truncate text-sm">{{ r.name }}</TableCell>
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
