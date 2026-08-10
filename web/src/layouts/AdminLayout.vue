<script setup lang="ts">
import { RouterLink, RouterView } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Button } from '@/components/ui/button'
import { Gauge, LogOut, ScrollText, Settings, ShieldCheck } from 'lucide-vue-next'

const auth = useAuthStore()
</script>

<template>
  <div class="flex min-h-screen">
    <!-- 侧边栏 -->
    <aside class="w-56 shrink-0 border-r bg-muted/30 flex flex-col">
      <div class="flex items-center gap-2 px-4 h-14 border-b">
        <ShieldCheck class="h-5 w-5 text-primary" />
        <span class="font-semibold">WAF 管理后台</span>
      </div>
      <nav class="flex-1 p-3 space-y-1">
        <RouterLink
          to="/dashboard"
          class="flex items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-accent"
        >
          <Gauge class="h-4 w-4" /> 仪表盘
        </RouterLink>
        <RouterLink
          to="/rules"
          class="flex items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-accent"
        >
          <ShieldCheck class="h-4 w-4" /> 规则管理
        </RouterLink>
        <RouterLink
          to="/events"
          class="flex items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-accent"
        >
          <ScrollText class="h-4 w-4" /> 攻击事件
        </RouterLink>
        <RouterLink
          to="/config"
          class="flex items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-accent"
        >
          <Settings class="h-4 w-4" /> 系统配置
        </RouterLink>
      </nav>
      <div class="p-3 border-t flex items-center justify-between">
        <span class="text-sm text-muted-foreground">{{ auth.username }}</span>
        <Button variant="ghost" size="sm" @click="auth.logout(); $router.push('/login')">
          <LogOut class="h-4 w-4" /> 退出
        </Button>
      </div>
    </aside>

    <!-- 主内容 -->
    <main class="flex-1 p-6 overflow-auto">
      <RouterView />
    </main>
  </div>
</template>
