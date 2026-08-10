import { defineStore } from 'pinia'
import { api, type SetupStatus } from '@/api'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('waf_token') || '',
    username: localStorage.getItem('waf_username') || '',
    setupDone: true,
  }),
  actions: {
    async login(username: string, password: string) {
      const data = await api.post<{ token: string }>('/auth/login', { username, password })
      this.token = data.token
      localStorage.setItem('waf_token', data.token)
      const me = await api.get<{ username: string }>('/auth/me')
      this.username = me.username
      localStorage.setItem('waf_username', me.username)
    },
    logout() {
      this.token = ''
      this.username = ''
      this.setupDone = true
      localStorage.removeItem('waf_token')
      localStorage.removeItem('waf_username')
    },
    // 检查首次引导是否完成（未完成则跳转引导页）
    async checkSetup() {
      if (!this.token) return
      const s = await api.get<SetupStatus>('/setup/status')
      this.setupDone = s.done
    },
    setSetupDone(v: boolean) {
      this.setupDone = v
    },
  },
})
