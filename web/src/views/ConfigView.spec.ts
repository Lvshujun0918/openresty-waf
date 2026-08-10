import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import ConfigView from '@/views/ConfigView.vue'

const apiMock = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn(),
}))

vi.mock('@/api', () => ({ api: apiMock }))

const fullConfig = {
  mode: 'active',
  modules: { ip_check: true, cc_check: true },
  cc: { rate: '100/60', ban_duration: 300 },
  block: { status: 403, html: '<h1>blocked</h1>' },
  log: { enabled: true, backend: 'file', dir: '/var/log/waf', redis_key: 'waf:event:list' },
  whitelist: { ips: ['127.0.0.1'], urls: [], user_agents: [] },
  blacklist: { ips: [], urls: [] },
  upload: { deny_ext: ['php'], deny_mime: [] },
  challenge: { enabled: true, mode: 'basic', cookie_ttl: 300, captcha: {} },
}

describe('ConfigView 系统配置页', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('加载使用单 /config 路径（不重复 /api 前缀）', async () => {
    apiMock.get.mockResolvedValueOnce({ config: fullConfig })
    mount(ConfigView)
    await flushPromises()
    expect(apiMock.get).toHaveBeenCalledWith('/config')
    expect(apiMock.get.mock.calls[0][0]).not.toContain('/api/config')
  })

  it('渲染后端返回的配置字段', async () => {
    apiMock.get.mockResolvedValueOnce({ config: fullConfig })
    const w = mount(ConfigView)
    await flushPromises()
    expect(w.text()).toContain('系统配置')
    // 运行模式 select 回显
    expect((w.find('select').element as HTMLSelectElement).value).toBe('active')
  })

  it('加载失败不崩溃并提示错误', async () => {
    apiMock.get.mockRejectedValueOnce(new Error('配置加载失败'))
    const w = mount(ConfigView)
    await flushPromises()
    expect(w.text()).toContain('系统配置')
    expect(w.text()).toContain('配置加载失败')
  })

  it('保存调用单 /config 路径并提示成功', async () => {
    apiMock.get.mockResolvedValueOnce({ config: fullConfig })
    apiMock.put.mockResolvedValueOnce({ status: 'ok' })
    const w = mount(ConfigView)
    await flushPromises()
    await w.find('button').trigger('click')
    await flushPromises()
    expect(apiMock.put).toHaveBeenCalledWith('/config', expect.any(Object))
    expect(w.text()).toContain('已保存并下发')
  })
})
