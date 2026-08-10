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

// 数组 <-> 逗号字符串
function toList(s: string): string[] {
  return s ? s.split(',').map((x) => x.trim()).filter(Boolean) : []
}
function toStr(arr: unknown[] | undefined): string {
  return (arr || []).join(', ')
}

// 名单等数组字段的编辑缓冲
const wlIps = ref('')
const wlUrls = ref('')
const wlUa = ref('')
const blIps = ref('')
const blUrls = ref('')
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
    config.cc = config.cc || {}
    config.block = config.block || {}
    config.log = config.log || {}
    config.whitelist = config.whitelist || {}
    config.blacklist = config.blacklist || {}
    config.upload = config.upload || {}
    config.challenge = config.challenge || {}
    config.challenge.captcha = config.challenge.captcha || {}
    wlIps.value = toStr(config.whitelist.ips)
    wlUrls.value = toStr(config.whitelist.urls)
    wlUa.value = toStr(config.whitelist.user_agents)
    blIps.value = toStr(config.blacklist.ips)
    blUrls.value = toStr(config.blacklist.urls)
    denyExt.value = toStr(config.upload.deny_ext)
    denyMime.value = toStr(config.upload.deny_mime)
  } catch (e: any) {
    msg.value = e.message || '配置加载失败'
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  msg.value = ''
  config.whitelist.ips = toList(wlIps.value)
  config.whitelist.urls = toList(wlUrls.value)
  config.whitelist.user_agents = toList(wlUa.value)
  config.blacklist.ips = toList(blIps.value)
  config.blacklist.urls = toList(blUrls.value)
  config.upload.deny_ext = toList(denyExt.value)
  config.upload.deny_mime = toList(denyMime.value)
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

      <!-- 黑白名单 -->
      <Card>
        <CardHeader><CardTitle>黑白名单</CardTitle></CardHeader>
        <CardContent class="grid grid-cols-2 gap-4">
          <div class="space-y-1.5">
            <Label>白名单 IP（逗号分隔，支持 CIDR）</Label>
            <textarea v-model="wlIps" rows="3" class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs" placeholder="127.0.0.1, 10.0.0.0/8" />
          </div>
          <div class="space-y-1.5">
            <Label>黑名单 IP（逗号分隔）</Label>
            <textarea v-model="blIps" rows="3" class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs" placeholder="1.2.3.4" />
          </div>
          <div class="space-y-1.5">
            <Label>白名单 URL（正则）</Label>
            <textarea v-model="wlUrls" rows="2" class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs" />
          </div>
          <div class="space-y-1.5">
            <Label>白名单 UA（正则）</Label>
            <textarea v-model="wlUa" rows="2" class="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs" />
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

      <!-- 人机验证 -->
      <Card>
        <CardHeader>
          <CardTitle>人机验证</CardTitle>
          <CardDescription>模式 basic（自包含）/ geetest / gitee（需配置 captcha_id/key）</CardDescription>
        </CardHeader>
        <CardContent class="grid grid-cols-2 gap-4">
          <label class="flex items-center gap-2 text-sm">
            <input v-model="config.challenge.enabled" type="checkbox" class="h-4 w-4" /> 启用
          </label>
          <div class="space-y-1.5">
            <Label>模式</Label>
            <select v-model="config.challenge.mode" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
              <option value="basic">basic</option>
              <option value="geetest">geetest</option>
              <option value="gitee">gitee</option>
            </select>
          </div>
          <div class="space-y-1.5">
            <Label>放行时长（秒）</Label>
            <Input v-model.number="config.challenge.cookie_ttl" type="number" />
          </div>
          <div class="space-y-1.5">
            <Label>签名密钥（生产务必修改）</Label>
            <Input v-model="config.challenge.cookie_secret" />
          </div>
          <div class="space-y-1.5">
            <Label>验证页路径</Label>
            <Input v-model="config.challenge.page_path" />
          </div>
          <div class="space-y-1.5">
            <Label>回调路径</Label>
            <Input v-model="config.challenge.verify_path" />
          </div>
          <div class="space-y-1.5">
            <Label>captcha_id（高级模式）</Label>
            <Input v-model="config.challenge.captcha.id" />
          </div>
          <div class="space-y-1.5">
            <Label>captcha_key（高级模式）</Label>
            <Input v-model="config.challenge.captcha.key" />
          </div>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
