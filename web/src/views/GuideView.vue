<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, type SetupGuide, type SetupStatus } from '@/api'
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
import { Check, Copy, Download, Plug, Server } from 'lucide-vue-next'

const status = ref<SetupStatus | null>(null)
const guide = ref<SetupGuide | null>(null)
const addr = ref('127.0.0.1:6379')
const password = ref('')
const db = ref(0)
const saving = ref(false)
const error = ref('')
const msg = ref('')
const copied = ref('')

async function load() {
  try {
    status.value = await api.get<SetupStatus>('/setup/status')
  } catch {
    status.value = null
  }
  if (status.value?.redis_configured) {
    addr.value = status.value.redis_addr || addr.value
    try {
      guide.value = await api.get<SetupGuide>(
        `/setup/guide?admin=${encodeURIComponent(window.location.origin)}`,
      )
    } catch (e: any) {
      error.value = e.message || '加载接入指引失败'
    }
  }
}

async function saveRedis() {
  saving.value = true
  error.value = ''
  msg.value = ''
  try {
    await api.post('/setup/redis', {
      addr: addr.value,
      password: password.value,
      db: Number(db.value),
    })
    msg.value = 'Redis 配置已保存并下发'
    await load()
  } catch (e: any) {
    error.value = e.message || '保存失败'
  } finally {
    saving.value = false
  }
}

async function copy(text: string, key: string) {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    error.value = '请手动复制'
  }
  copied.value = key
  setTimeout(() => (copied.value = ''), 2000)
}

onMounted(load)
</script>

<template>
  <div class="space-y-4">
    <div>
      <h1 class="text-2xl font-semibold flex items-center gap-2">
        <Plug class="h-6 w-6" /> 接入指引
      </h1>
      <p class="text-sm text-muted-foreground">配置 Redis 连接，并接入本机已部署的 OpenResty</p>
    </div>

    <div class="grid gap-4 lg:grid-cols-2">
      <!-- Redis 配置 -->
      <Card>
        <CardHeader>
          <CardTitle class="flex items-center gap-2">
            <Server class="h-5 w-5" /> Redis 连接
          </CardTitle>
          <CardDescription class="flex items-center gap-2">
            当前状态：
            <Badge :variant="status?.redis_configured ? 'default' : 'outline'">
              {{ status?.redis_configured ? '已配置' : '未配置' }}
            </Badge>
            <span v-if="status?.redis_addr"> · {{ status.redis_addr }}</span>
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-4">
          <div class="space-y-2">
            <Label>Redis 地址</Label>
            <Input v-model="addr" placeholder="如 192.168.1.20:6379" />
          </div>
          <div class="grid grid-cols-2 gap-4">
            <div class="space-y-2">
              <Label>密码（无则留空）</Label>
              <Input v-model="password" type="password" placeholder="redis 密码" />
            </div>
            <div class="space-y-2">
              <Label>数据库编号</Label>
              <Input v-model="db" type="number" />
            </div>
          </div>
          <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
          <p v-if="msg" class="text-sm text-primary">{{ msg }}</p>
          <Button class="w-full" :disabled="saving" @click="saveRedis">
            {{ saving ? '测试并保存…' : '测试并保存' }}
          </Button>
        </CardContent>
      </Card>

      <!-- OpenResty 接入指引 -->
      <Card>
        <CardHeader>
          <CardTitle>接入本机 OpenResty</CardTitle>
          <CardDescription>
            {{ guide ? '在 OpenResty 服务器上执行以下命令即可接入' : '请先在上方配置 Redis' }}
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-5">
          <template v-if="guide">
            <div class="space-y-2">
              <div class="flex items-center justify-between">
                <Label>一键安装命令（在 OpenResty 服务器执行）</Label>
                <Button variant="ghost" size="sm" @click="copy(guide.install_command, 'install')">
                  <Copy v-if="copied !== 'install'" class="h-4 w-4" />
                  <Check v-else class="h-4 w-4 text-primary" />
                  {{ copied === 'install' ? '已复制' : '复制' }}
                </Button>
              </div>
              <pre
                class="rounded-md border bg-muted/40 p-3 text-xs overflow-x-auto"
              >{{ guide.install_command }}</pre>
            </div>

            <div class="space-y-2">
              <div class="flex items-center justify-between">
                <Label>nginx.conf 接入配置</Label>
                <Button variant="ghost" size="sm" @click="copy(guide.nginx_config, 'nginx')">
                  <Copy v-if="copied !== 'nginx'" class="h-4 w-4" />
                  <Check v-else class="h-4 w-4 text-primary" />
                  {{ copied === 'nginx' ? '已复制' : '复制' }}
                </Button>
              </div>
              <pre
                class="rounded-md border bg-muted/40 p-3 text-xs overflow-x-auto whitespace-pre-wrap"
              >{{ guide.nginx_config }}</pre>
            </div>

            <div class="flex items-center justify-between rounded-md border bg-muted/30 px-3 py-2 text-sm">
              <span>Redis：<code class="font-mono">{{ guide.redis.addr }}</code></span>
              <a :href="guide.download_url" class="text-primary hover:underline inline-flex items-center gap-1" download>
                <Download class="h-4 w-4" /> 下载 WAF 组件
              </a>
            </div>
          </template>
          <p v-else class="text-sm text-muted-foreground">
            配置 Redis 并保存后，此处将显示一键安装命令与 nginx 配置。
          </p>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
