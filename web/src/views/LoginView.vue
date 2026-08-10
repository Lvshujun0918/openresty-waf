<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ScrollText, ShieldCheck, Siren, Zap } from 'lucide-vue-next'

const router = useRouter()
const auth = useAuthStore()
const username = ref('admin')
const password = ref('')
const loading = ref(false)
const error = ref('')

async function handleLogin() {
  loading.value = true
  error.value = ''
  try {
    await auth.login(username.value, password.value)
    router.push('/dashboard')
  } catch (e: any) {
    error.value = e.message || '登录失败'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="min-h-screen grid lg:grid-cols-2 bg-background">
    <!-- 品牌面板（签名元素：雷达光晕 + 深海军蓝） -->
    <div
      class="hidden lg:flex flex-col justify-between relative overflow-hidden p-10 text-white bg-gradient-to-br from-[oklch(0.22_0.05_260)] via-[oklch(0.16_0.05_260)] to-[oklch(0.11_0.04_260)]"
    >
      <!-- 雷达光晕装饰 -->
      <div class="pointer-events-none absolute -right-40 -top-40 h-[28rem] w-[28rem] rounded-full border border-brand-400/20" />
      <div class="pointer-events-none absolute -right-20 -top-20 h-[20rem] w-[20rem] rounded-full border border-brand-400/20" />
      <div class="pointer-events-none absolute -right-10 -top-10 h-[12rem] w-[12rem] rounded-full bg-brand-500/10 blur-2xl" />

      <!-- 顶部品牌 -->
      <div class="relative flex items-center gap-3">
        <div class="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-brand-400 to-brand-700 shadow-lg shadow-brand-900/50">
          <ShieldCheck class="h-5 w-5 text-white" />
        </div>
        <div>
          <div class="font-semibold text-lg tracking-wide">WAF 防御台</div>
          <div class="text-xs text-brand-200/70">OpenResty 安全防护</div>
        </div>
      </div>

      <!-- 中部宣传 -->
      <div class="relative space-y-8">
        <h1 class="text-3xl font-semibold leading-snug tracking-tight">
          为你的 OpenResty 站点<br />
          <span class="bg-gradient-to-r from-brand-300 to-brand-100 bg-clip-text text-transparent">筑起安全防线</span>
        </h1>
        <div class="space-y-4 text-sm text-brand-100/80">
          <div class="flex items-center gap-3">
            <div class="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-500/20 text-brand-200"><Siren class="h-4 w-4" /></div>
            规则引擎实时拦截 SQL 注入、XSS、扫描器等攻击
          </div>
          <div class="flex items-center gap-3">
            <div class="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-500/20 text-brand-200"><ScrollText class="h-4 w-4" /></div>
            攻击事件全量可视化，类型分布一目了然
          </div>
          <div class="flex items-center gap-3">
            <div class="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-500/20 text-brand-200"><Zap class="h-4 w-4" /></div>
            规则与配置秒级热更新，无需重启服务
          </div>
        </div>
      </div>

      <!-- 底部 -->
      <div class="relative flex items-center gap-2 text-xs text-brand-200/60">
        <span class="h-1.5 w-1.5 rounded-full bg-success" />
        OpenResty WAF · 管理后台
      </div>
    </div>

    <!-- 登录表单 -->
    <div class="flex items-center justify-center p-6">
      <Card class="w-full max-w-sm border-border/70 shadow-lg shadow-brand-900/5">
        <CardHeader class="items-center text-center">
          <div class="mb-2 flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-brand-500 to-brand-700 shadow-md shadow-brand-900/20">
            <ShieldCheck class="h-6 w-6 text-white" />
          </div>
          <CardTitle class="text-xl">登录管理后台</CardTitle>
          <CardDescription>输入管理员账号以继续</CardDescription>
        </CardHeader>
        <CardContent>
          <form class="space-y-4" @submit.prevent="handleLogin">
            <div class="space-y-2">
              <Label for="username">用户名</Label>
              <Input id="username" v-model="username" required autocomplete="username" />
            </div>
            <div class="space-y-2">
              <Label for="password">密码</Label>
              <Input
                id="password"
                v-model="password"
                type="password"
                required
                autocomplete="current-password"
              />
            </div>
            <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
            <Button type="submit" class="w-full" :disabled="loading">
              {{ loading ? '登录中…' : '登 录' }}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
