<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
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
import { Copy, Check, Server, ShieldCheck } from 'lucide-vue-next'

const router = useRouter()
const auth = useAuthStore()

const step = ref(1)
const addr = ref('127.0.0.1:6379')
const password = ref('')
const db = ref(0)
const loading = ref(false)
const error = ref('')
const guide = ref<SetupGuide | null>(null)
const copied = ref('')

async function saveRedis() {
  loading.value = true
  error.value = ''
  try {
    await api.post('/setup/redis', {
      addr: addr.value,
      password: password.value,
      db: Number(db.value),
    })
    await loadGuide()
    step.value = 2
  } catch (e: any) {
    error.value = e.message || '保存失败'
  } finally {
    loading.value = false
  }
}

async function loadGuide() {
  guide.value = await api.get<SetupGuide>(
    `/setup/guide?admin=${encodeURIComponent(window.location.origin)}`,
  )
}

async function copy(text: string, key: string) {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    // 剪贴板不可用时选中文本
    error.value = '请手动复制'
    setTimeout(() => (error.value = ''), 2000)
  }
  copied.value = key
  setTimeout(() => (copied.value = ''), 2000)
}

function finish() {
  auth.setSetupDone(true)
  router.push('/dashboard')
}

onMounted(async () => {
  const s = await api.get<SetupStatus>('/setup/status')
  if (s.done) {
    auth.setSetupDone(true)
    router.push('/dashboard')
  }
})
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-muted/40 p-4">
    <div class="w-full max-w-2xl space-y-6">
      <div class="text-center">
        <ShieldCheck class="mx-auto h-10 w-10 text-primary mb-2" />
        <h1 class="text-2xl font-semibold">欢迎使用 OpenResty WAF</h1>
        <p class="text-sm text-muted-foreground">完成两步引导即可开始使用</p>
      </div>

      <!-- 步骤指示 -->
      <div class="flex items-center justify-center gap-4 text-sm">
        <Badge :variant="step >= 1 ? 'default' : 'outline'">1 · 连接 Redis</Badge>
        <div class="h-px w-10 bg-border" />
        <Badge :variant="step >= 2 ? 'default' : 'outline'">2 · 接入 OpenResty</Badge>
      </div>

      <!-- 步骤 1：Redis -->
      <Card v-if="step === 1">
        <CardHeader>
          <CardTitle class="flex items-center gap-2">
            <Server class="h-5 w-5" /> 配置 Redis
          </CardTitle>
          <CardDescription>
            填写你的 Redis 连接信息（规则下发与攻击事件队列使用），后台会先测试连通性
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
          <Button class="w-full" :disabled="loading" @click="saveRedis">
            {{ loading ? '测试并保存…' : '测试并保存' }}
          </Button>
        </CardContent>
      </Card>

      <!-- 步骤 2：接入 OpenResty -->
      <Card v-if="step === 2 && guide">
        <CardHeader>
          <CardTitle>接入本机已部署的 OpenResty</CardTitle>
          <CardDescription>
            在运行 OpenResty 的服务器上执行以下命令，自动安装 WAF 组件并生成配置
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-5">
          <div class="space-y-2">
            <div class="flex items-center justify-between">
              <Label>一键安装命令（在本机 OpenResty 服务器执行）</Label>
              <Button variant="ghost" size="sm" @click="copy(guide.install_command, 'install')">
                <Copy v-if="copied !== 'install'" class="h-4 w-4" />
                <Check v-else class="h-4 w-4 text-primary" />
                {{ copied === 'install' ? '已复制' : '复制' }}
              </Button>
            </div>
            <pre class="rounded-md border bg-muted/40 p-3 text-xs overflow-x-auto">{{ guide.install_command }}</pre>
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
            <pre class="rounded-md border bg-muted/40 p-3 text-xs overflow-x-auto whitespace-pre-wrap">{{ guide.nginx_config }}</pre>
          </div>

          <div class="flex items-center justify-between rounded-md border bg-muted/30 px-3 py-2 text-sm">
            <span>Redis：<code class="font-mono">{{ guide.redis.addr }}</code></span>
            <a :href="guide.download_url" class="text-primary hover:underline" download>
              手动下载 WAF 组件
            </a>
          </div>

          <Button class="w-full" @click="finish">完成，进入管理后台</Button>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
