<script setup lang="ts">
import { RouterLink, RouterView } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Button } from '@/components/ui/button'
import { Gauge, LogOut, Plug, ScrollText, Settings, ShieldAlert, ShieldCheck } from 'lucide-vue-next'
import { cn } from '@/lib/utils'

const auth = useAuthStore()

const navItems = [
  { to: '/dashboard', label: '仪表盘', icon: Gauge },
  { to: '/rules', label: '规则管理', icon: ShieldCheck },
  { to: '/events', label: '攻击事件', icon: ScrollText },
  { to: '/cc', label: 'CC 防刷', icon: ShieldAlert },
  { to: '/config', label: '系统配置', icon: Settings },
  { to: '/guide', label: '接入指引', icon: Plug },
]
</script>

<template>
  <div class="flex min-h-screen bg-background">
    <!-- 侧边栏：深海军蓝指挥台 -->
    <aside class="w-60 shrink-0 bg-sidebar text-sidebar-foreground flex flex-col border-r border-sidebar-border">
      <!-- 品牌区 -->
      <div class="flex items-center gap-2.5 px-5 h-16 border-b border-sidebar-border">
        <div class="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-brand-400 to-brand-700 shadow-lg shadow-brand-900/40">
          <ShieldCheck class="h-5 w-5 text-white" />
        </div>
        <div class="leading-tight">
          <div class="font-semibold text-[15px] text-white tracking-wide">WAF 防御台</div>
          <div class="text-[11px] text-sidebar-foreground/60">OpenResty 安全防护</div>
        </div>
      </div>

      <!-- 导航 -->
      <nav class="flex-1 p-3 space-y-1">
        <RouterLink v-for="item in navItems" :key="item.to" :to="item.to" v-slot="{ isActive }">
          <div
            :class="cn(
              'group relative flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors',
              isActive
                ? 'bg-sidebar-muted text-white font-medium'
                : 'text-sidebar-foreground/80 hover:bg-sidebar-muted/60 hover:text-sidebar-foreground',
            )"
          >
            <!-- 激活指示条 -->
            <span
              v-if="isActive"
              class="absolute left-0 top-1/2 -translate-y-1/2 h-5 w-1 rounded-full bg-gradient-to-b from-brand-400 to-brand-500"
            />
            <component :is="item.icon" class="h-4 w-4" />
            {{ item.label }}
          </div>
        </RouterLink>
      </nav>

      <!-- 用户区 -->
      <div class="p-3 border-t border-sidebar-border flex items-center justify-between">
        <div class="flex items-center gap-2 min-w-0">
          <div class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-brand-600/40 text-xs font-semibold text-white">
            {{ (auth.username || 'A').charAt(0).toUpperCase() }}
          </div>
          <span class="text-sm text-sidebar-foreground truncate">{{ auth.username }}</span>
        </div>
        <Button
          variant="ghost"
          size="sm"
          class="text-sidebar-foreground/70 hover:text-white hover:bg-sidebar-muted"
          @click="auth.logout(); $router.push('/login')"
        >
          <LogOut class="h-4 w-4" />
        </Button>
      </div>
    </aside>

    <!-- 主内容 -->
    <main class="flex-1 overflow-auto">
      <!-- 顶部品牌渐变细条 -->
      <div class="h-1 bg-gradient-to-r from-brand-600 via-brand-400 to-brand-600" />
      <div class="p-6">
        <RouterView />
      </div>
    </main>
  </div>
</template>
