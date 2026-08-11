<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { api } from '@/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Settings } from 'lucide-vue-next'

const config = reactive<any>({
  mode: 'active',
  modules: {},
  detection: {},
  cc: {},
  block: {},
  log: {},
  whitelist: {},
  blacklist: {},
  upload: {},
  challenge: { captcha: {} },
})
const loading = ref(false)
const saving = ref(false)
const msg = ref('')
const excludePaths = ref('')
const paranoiaLevel = ref('1')

// 数组 <-> 逗号字符串
function toList(s: string): string[] {
  return s ? s.split(',').map((x) => x.trim()).filter(Boolean) : []
}
function toStr(arr: unknown[] | undefined): string {
  return (arr || []).join(', ')
}

// 上传字段编辑缓冲
const denyExt = ref('')
const denyMime = ref('')

const modules = [
  ['ip_check', 'IP 黑白名单'],
  ['ua_check', 'UA 检测'],
  ['url_check', 'URL 检测'],
  ['args_check', '参数检测'],
  ['cookie_check', 'Cookie 检测'],
  ['header_check', '请求头检测'],
  ['post_check', 'POST 检测'],
  ['upload_check', '上传检测'],
  ['cc_check', 'CC 防刷'],
  ['challenge', '人机验证'],
  ['protocol_check', '协议异常'],
  ['leak_check', '敏感文件'],
] as const

async function load() {
  loading.value = true
  try {
    const d = await api.get<{ config: any }>('/config')
    Object.assign(config, d.config || {})
    config.modules = config.modules || {}
    config.detection = config.detection || {}
    config.cc = config.cc || {}
    config.block = config.block || {}
    config.log = config.log || {}
    config.whitelist = config.whitelist || {}
    config.blacklist = config.blacklist || {}
    config.upload = config.upload || {}
    config.challenge = config.challenge || {}
    config.challenge.captcha = config.challenge.captcha || {}
    denyExt.value = toStr(config.upload.deny_ext)
    denyMime.value = toStr(config.upload.deny_mime)
    excludePaths.value = toStr(config.detection.exclude_paths)
    paranoiaLevel.value = String(config.detection.paranoia_level ?? 1)
  } catch (e: any) {
    msg.value = e.message || '配置加载失败'
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  msg.value = ''
  config.upload.deny_ext = toList(denyExt.value)
  config.upload.deny_mime = toList(denyMime.value)
  config.detection = config.detection || {}
  config.detection.exclude_paths = toList(excludePaths.value)
  config.detection.paranoia_level = Number(paranoiaLevel.value)
  try {
    await api.put('/config', { config })
    msg.value = '已保存并下发，引擎将在数秒内热更新生效'
  } catch (e: any) {
    msg.value = e.message || '保存失败'
  } finally {
    saving.value = false
    setTimeout(() => (msg.value = ''), 4000)
  }
}

onMounted(load)
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-semibold flex items-center gap-2">
          <Settings class="h-6 w-6" /> 系统配置
        </h1>
        <p class="text-sm text-muted-foreground">统一管理 WAF 运行配置，保存后自动下发热更新（无需改 Lua）</p>
      </div>
      <div class="flex items-center gap-3">
        <span v-if="msg" class="text-sm text-muted-foreground">{{ msg }}</span>
        <Button :disabled="saving || loading" @click="save">{{ saving ? '保存中…' : '保存并下发' }}</Button>
      </div>
    </div>

    <div v-if="!loading" class="grid gap-4">
      <!-- 基本 -->
      <Card>
        <CardHeader><CardTitle>基本</CardTitle></CardHeader>
        <CardContent class="space-y-3">
          <div class="space-y-1.5 max-w-xs">
            <Label>运行模式</Label>
            <select v-model="config.mode" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
              <option value="active">active · 拦截模式</option>
              <option value="detect">detect · 监控模式（仅记录）</option>
              <option value="off">off · 放行模式（旁路）</option>
            </select>
          </div>
        </CardContent>
      </Card>

      <!-- 模块开关 -->
      <Card>
        <CardHeader><CardTitle>检测模块</CardTitle></CardHeader>
        <CardContent class="grid grid-cols-2 md:grid-cols-3 gap-3">
          <label v-for="[key, label] in modules" :key="key" class="flex items-center gap-2 text-sm rounded-md border px-3 py-2 cursor-pointer">
            <input v-model="config.modules[key]" type="checkbox" class="h-4 w-4" />
            {{ label }}
          </label>
        </CardContent>
      </Card>

      <!-- 豁免路径（降低误报） -->
      <Card>
        <CardHeader>
          <CardTitle>检测策略</CardTitle>
          <CardDescription>CRS 偏执级别与规则检测豁免</CardDescription>
        </CardHeader>
        <CardContent class="space-y-4">
          <div class="space-y-1.5 max-w-xs">
            <Label>CRS 偏执级别</Label>
            <select v-model="paranoiaLevel" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
              <option value="1">PL1 · 核心规则（低误报，推荐）</option>
              <option value="2">PL2 · 含启发式检测</option>
              <option value="3">PL3 · 更严格</option>
              <option value="4">PL4 · 最严格（高误报风险）</option>
            </select>
            <p class="text-xs text-muted-foreground">
              档位越高启用的 CRS 规则越多、检出越高但误报越高；建议默认 PL1
            </p>
          </div>
          <div class="space-y-1.5">
            <Label>检测豁免路径（逗号分隔）</Label>
            <textarea
              v-model="excludePaths"
              rows="3"
              placeholder="/api/auth/, /api/public/"
              class="w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            ></textarea>
            <p class="text-xs text-muted-foreground">
              命中这些路径前缀时跳过规则检测（IP 黑白名单 / CC 仍生效），用于规避 JSON API 误报
            </p>
          </div>
        </CardContent>
      </Card>

      <!-- 拦截响应 -->
      <Card>
        <CardHeader><CardTitle>拦截响应</CardTitle></CardHeader>
        <CardContent class="space-y-3">
          <div class="space-y-1.5 max-w-xs">
            <Label>状态码</Label>
            <Input v-model.number="config.block.status" type="number" />
          </div>
          <div class="space-y-1.5">
            <Label>拦截页面（HTML）</Label>
            <textarea v-model="config.block.html" rows="6" class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs" />
          </div>
        </CardContent>
      </Card>

      <!-- 日志 -->
      <Card>
        <CardHeader><CardTitle>日志</CardTitle></CardHeader>
        <CardContent class="grid grid-cols-2 gap-4 max-w-lg">
          <label class="flex items-center gap-2 text-sm">
            <input v-model="config.log.enabled" type="checkbox" class="h-4 w-4" /> 启用日志
          </label>
          <div class="space-y-1.5">
            <Label>后端</Label>
            <select v-model="config.log.backend" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
              <option value="file">file · 本地文件</option>
              <option value="redis">redis · 推送队列（后台消费）</option>
            </select>
          </div>
          <div class="space-y-1.5">
            <Label>目录（file 后端）</Label>
            <Input v-model="config.log.dir" />
          </div>
          <div class="space-y-1.5">
            <Label>队列键（redis 后端）</Label>
            <Input v-model="config.log.redis_key" />
          </div>
        </CardContent>
      </Card>

      <!-- 上传 -->
      <Card>
        <CardHeader><CardTitle>文件上传</CardTitle></CardHeader>
        <CardContent class="grid grid-cols-2 gap-4">
          <div class="space-y-1.5">
            <Label>禁止后缀（逗号分隔）</Label>
            <Input v-model="denyExt" />
          </div>
          <div class="space-y-1.5">
            <Label>禁止 MIME（逗号分隔）</Label>
            <Input v-model="denyMime" />
          </div>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
