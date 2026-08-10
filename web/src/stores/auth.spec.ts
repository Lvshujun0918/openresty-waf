import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'

const apiMock = vi.hoisted(() => ({
  post: vi.fn(),
  get: vi.fn(),
}))

vi.mock('@/api', () => ({ api: apiMock }))

describe('auth store', () => {
  beforeEach(() => {
    localStorage.clear()
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('初始状态从 localStorage 恢复 token', () => {
    localStorage.setItem('waf_token', 'saved-token')
    const store = useAuthStore()
    expect(store.token).toBe('saved-token')
  })

  it('login 保存 token 与用户名', async () => {
    apiMock.post.mockResolvedValueOnce({ token: 't1' })
    apiMock.get.mockResolvedValueOnce({ username: 'admin' })

    const store = useAuthStore()
    await store.login('admin', 'admin123')

    expect(apiMock.post).toHaveBeenCalledWith('/auth/login', { username: 'admin', password: 'admin123' })
    expect(store.token).toBe('t1')
    expect(store.username).toBe('admin')
    expect(localStorage.getItem('waf_token')).toBe('t1')
    expect(localStorage.getItem('waf_username')).toBe('admin')
  })

  it('logout 清空状态与 localStorage', () => {
    localStorage.setItem('waf_token', 't')
    localStorage.setItem('waf_username', 'u')
    const store = useAuthStore()
    store.token = 't'
    store.username = 'u'

    store.logout()

    expect(store.token).toBe('')
    expect(store.username).toBe('')
    expect(store.setupDone).toBe(true)
    expect(localStorage.getItem('waf_token')).toBeNull()
    expect(localStorage.getItem('waf_username')).toBeNull()
  })

  it('checkSetup 有 token 时请求并更新 setupDone', async () => {
    apiMock.get.mockResolvedValueOnce({ done: false, redis_configured: false })
    const store = useAuthStore()
    store.token = 't'

    await store.checkSetup()

    expect(apiMock.get).toHaveBeenCalledWith('/setup/status')
    expect(store.setupDone).toBe(false)
  })

  it('checkSetup 完成引导后 setupDone 为 true', async () => {
    apiMock.get.mockResolvedValueOnce({ done: true, redis_configured: true })
    const store = useAuthStore()
    store.token = 't'
    store.setupDone = false

    await store.checkSetup()

    expect(store.setupDone).toBe(true)
  })

  it('checkSetup 无 token 时不发请求', async () => {
    const store = useAuthStore()
    await store.checkSetup()
    expect(apiMock.get).not.toHaveBeenCalled()
  })

  it('setSetupDone 手动设置', () => {
    const store = useAuthStore()
    store.setSetupDone(false)
    expect(store.setupDone).toBe(false)
    store.setSetupDone(true)
    expect(store.setupDone).toBe(true)
  })
})
