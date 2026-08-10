import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('@/views/LoginView.vue') },
    { path: '/setup', name: 'setup', component: () => import('@/views/SetupView.vue') },
    {
      path: '/',
      component: () => import('@/layouts/AdminLayout.vue'),
      redirect: '/dashboard',
      children: [
        { path: 'dashboard', name: 'dashboard', component: () => import('@/views/DashboardView.vue') },
        { path: 'rules', name: 'rules', component: () => import('@/views/RulesView.vue') },
        { path: 'events', name: 'events', component: () => import('@/views/EventsView.vue') },
        { path: 'config', name: 'config', component: () => import('@/views/ConfigView.vue') },
        { path: 'guide', name: 'guide', component: () => import('@/views/GuideView.vue') },
        { path: 'cc', name: 'cc', component: () => import('@/views/CcRulesView.vue') },
      ],
    },
  ],
})

// 全局路由守卫：登录 / 首次引导
router.beforeEach(async (to) => {
  const auth = useAuthStore()
  if (to.name !== 'login' && !auth.token) {
    return { name: 'login' }
  }
  if (to.name === 'login' && auth.token) {
    return { name: 'dashboard' }
  }
  // 已登录：非引导页先确认引导状态
  if (auth.token && to.name !== 'setup') {
    await auth.checkSetup()
    if (!auth.setupDone) {
      return { name: 'setup' }
    }
  }
  if (to.name === 'setup' && auth.setupDone && auth.token) {
    return { name: 'dashboard' }
  }
})

export default router
