import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { api } from '@/api/index'

const fetchMock = vi.fn()

// 简易 Response 替身（避免依赖环境全局 fetch/Response）
function jsonRes(data: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => data,
  }
}

// 替换 window.location 为可写对象（jsdom 中 location.href 赋值会触发导航告警）
function stubLocation() {
  const loc = { href: 'http://localhost/' }
  Object.defineProperty(window, 'location', { value: loc, writable: true })
  return loc
}

describe('api 请求封装', () => {
  let loc: { href: string }

  beforeEach(() => {
    localStorage.clear()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    loc = stubLocation()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('GET 拼接 /api 前缀并携带 token', async () => {
    localStorage.setItem('waf_token', 'tok123')
    fetchMock.mockResolvedValueOnce(jsonRes({ items: [] }))

    const data = await api.get('/rules')
    expect(data).toEqual({ items: [] })

    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/rules')
    expect(init.method ?? 'GET').toBe('GET')
    expect(init.headers.Authorization).toBe('Bearer tok123')
    expect(init.headers['Content-Type']).toBe('application/json')
  })

  it('无 token 时不携带 Authorization', async () => {
    fetchMock.mockResolvedValueOnce(jsonRes({}))
    await api.get('/health')
    const [, init] = fetchMock.mock.calls[0]
    expect(init.headers.Authorization).toBeUndefined()
  })

  it('POST 序列化 JSON body', async () => {
    fetchMock.mockResolvedValueOnce(jsonRes({ status: 'ok' }))
    await api.post('/auth/login', { username: 'admin', password: 'x' })
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/auth/login')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body)).toEqual({ username: 'admin', password: 'x' })
  })

  it('PUT / PATCH / DELETE 使用对应方法', async () => {
    fetchMock.mockResolvedValueOnce(jsonRes({}))
    await api.put('/config', { mode: 'detect' })
    expect(fetchMock.mock.calls[0][1].method).toBe('PUT')

    fetchMock.mockResolvedValueOnce(jsonRes({}))
    await api.patch('/rules/1/enabled', { enabled: false })
    expect(fetchMock.mock.calls[1][1].method).toBe('PATCH')

    fetchMock.mockResolvedValueOnce(jsonRes({}))
    await api.delete('/rules/1')
    expect(fetchMock.mock.calls[2][1].method).toBe('DELETE')
  })

  it('401 清除 token 并跳转登录页', async () => {
    localStorage.setItem('waf_token', 'expired')
    fetchMock.mockResolvedValueOnce(jsonRes({ error: '登录已失效' }, 401))

    await expect(api.get('/rules')).rejects.toThrow('登录已失效')
    expect(localStorage.getItem('waf_token')).toBeNull()
    expect(loc.href).toBe('/login')
  })

  it('非 2xx 抛错并带后端 error 信息', async () => {
    fetchMock.mockResolvedValueOnce(jsonRes({ error: 'Redis 未配置' }, 400))
    await expect(api.post('/setup/redis', { addr: 'x' })).rejects.toThrow('Redis 未配置')
  })

  it('非 2xx 且响应非 JSON 时抛通用错误', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 500,
      json: async () => {
        throw new Error('parse error')
      },
    })
    await expect(api.get('/rules')).rejects.toThrow('请求失败: 500')
  })

  it('成功响应解析 JSON', async () => {
    fetchMock.mockResolvedValueOnce(jsonRes({ total: 10 }))
    const data = await api.get('/events')
    expect(data).toEqual({ total: 10 })
  })
})
