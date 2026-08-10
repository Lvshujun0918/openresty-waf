import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import ChallengeView from '@/views/ChallengeView.vue'

const apiMock = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn(),
}))

vi.mock('@/api', () => ({ api: apiMock }))

const config = {
  mode: 'active',
  challenge: {
    enabled: true,
    mode: 'geetest',
    cookie_name: 'waf_pass',
    cookie_secret: 'secret',
    cookie_ttl: 300,
    page_path: '/__waf_challenge__',
    verify_path: '/__waf_challenge_verify__',
    trigger_paths: ['/admin/', '/api/login'],
    captcha: { id: 'cid', key: 'ckey', verify_api: 'https://x/validate', sdk: 'https://x/gt4.js' },
  },
}

describe('ChallengeView 人机验证页', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('加载并回显人机验证配置', async () => {
    apiMock.get.mockResolvedValueOnce({ config })
    const w = mount(ChallengeView)
    await flushPromises()

    expect(apiMock.get).toHaveBeenCalledWith('/config')
    expect(w.text()).toContain('人机验证')
    expect((w.find('select').element as HTMLSelectElement).value).toBe('geetest')
    const ttl = w.findAll('input').find((i) => (i.element as HTMLInputElement).value === '300')
    expect(ttl).toBeTruthy()
  })

  it('保存调用 /config 并提示成功', async () => {
    apiMock.get.mockResolvedValueOnce({ config })
    apiMock.put.mockResolvedValueOnce({ status: 'ok' })
    const w = mount(ChallengeView)
    await flushPromises()

    await w.find('button').trigger('click')
    await flushPromises()

    expect(apiMock.put).toHaveBeenCalledWith('/config', expect.objectContaining({
      config: expect.objectContaining({ challenge: expect.objectContaining({ mode: 'geetest' }) }),
    }))
    expect(w.text()).toContain('已保存并下发')
  })

  it('回显手动触发路径到多行输入框', async () => {
    apiMock.get.mockResolvedValueOnce({ config })
    const w = mount(ChallengeView)
    await flushPromises()

    const ta = w.find('textarea')
    expect(ta.exists()).toBe(true)
    expect((ta.element as HTMLTextAreaElement).value).toBe('/admin/\n/api/login')
  })

  it('保存时手动触发路径转为数组', async () => {
    apiMock.get.mockResolvedValueOnce({ config })
    apiMock.put.mockResolvedValueOnce({ status: 'ok' })
    const w = mount(ChallengeView)
    await flushPromises()

    const ta = w.find('textarea')
    ;(ta.element as HTMLTextAreaElement).value = '/admin/\n /api/login \n\n/pay'
    await ta.trigger('input')
    await w.find('button').trigger('click')
    await flushPromises()

    expect(apiMock.put).toHaveBeenCalledWith('/config', expect.objectContaining({
      config: expect.objectContaining({
        challenge: expect.objectContaining({
          trigger_paths: ['/admin/', '/api/login', '/pay'],
        }),
      }),
    }))
  })

  it('加载失败不崩溃', async () => {
    apiMock.get.mockRejectedValueOnce(new Error('加载失败'))
    const w = mount(ChallengeView)
    await flushPromises()
    expect(w.text()).toContain('人机验证')
    expect(w.text()).toContain('加载失败')
  })
})
