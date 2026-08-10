import { defineStore } from 'pinia'
import { api } from '@/api'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('waf_token') || '',
    username: localStorage.getItem('waf_username') || '',
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
      localStorage.removeItem('waf_token')
      localStorage.removeItem('waf_username')
    },
  },
})
