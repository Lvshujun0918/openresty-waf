import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import IpListView from '@/views/IpListView.vue'

const apiMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn(),
}))

vi.mock('@/api', () => ({ api: apiMock }))

const config = {
  mode: 'active',
  whitelist: { ips: ['127.0.0.1', '10.0.0.0/8'], urls: ['/favicon.ico'], user_agents: [] },
  blacklist: { ips: ['1.2.3.4'], urls: [] },
}
const sub = {
  id: 1,
  name: '威胁情报',
  url: 'https://example.com/ips.txt',
  type: 'blacklist',
  interval_min: 60,
  enabled: true,
  last_status: 'ok',
  last_count: 42,
}

describe('IpListView 黑白名单页', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.stubGlobal('confirm', vi.fn(() => true))
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('加载并渲染手动名单与订阅列表', async () => {
    apiMock.get.mockResolvedValueOnce({ config })
    apiMock.get.mockResolvedValueOnce([sub])

    const w = mount(IpListView)
    await flushPromises()

    expect(w.text()).toContain('IP 黑白名单')
    // 手动名单在 textarea 的 value 中（非文本节点）
    const textareas = w.findAll('textarea')
    expect((textareas[0].element as HTMLTextAreaElement).value).toContain('127.0.0.1')
    expect((textareas[1].element as HTMLTextAreaElement).value).toContain('1.2.3.4')
    expect(w.text()).toContain('威胁情报')
    expect(w.text()).toContain('https://example.com/ips.txt')
    expect(w.text()).toContain('42')
  })

  it('保存手动名单调用 /config', async () => {
    apiMock.get.mockResolvedValueOnce({ config })
    apiMock.get.mockResolvedValueOnce([])
    apiMock.put.mockResolvedValueOnce({ status: 'ok' })

    const w = mount(IpListView)
    await flushPromises()

    await w.findAll('button').find((b) => b.text() === '保存并下发')!.trigger('click')
    await flushPromises()

    expect(apiMock.put).toHaveBeenCalledWith('/config', expect.any(Object))
    expect(w.text()).toContain('名单已保存并下发')
  })

  it('添加订阅源', async () => {
    apiMock.get.mockResolvedValueOnce({ config })
    apiMock.get.mockResolvedValueOnce([])
    apiMock.post.mockResolvedValueOnce({ id: 2 })
    apiMock.get.mockResolvedValueOnce([{ ...sub, id: 2, name: '新源' }])

    const w = mount(IpListView)
    await flushPromises()

    const inputs = w.findAll('input')
    // 订阅表单输入（名称、URL、周期）+ 手动名单 textarea 不在 input 中
    await inputs[0].setValue('新源')
    await inputs[1].setValue('https://example.com/2.txt')
    await w.findAll('button').find((b) => b.text() === '添加订阅')!.trigger('click')
    await flushPromises()

    expect(apiMock.post).toHaveBeenCalledWith('/ip-list-subs', expect.objectContaining({
      name: '新源',
      url: 'https://example.com/2.txt',
      type: 'blacklist',
    }))
    expect(w.text()).toContain('新源')
  })

  it('立即同步订阅源', async () => {
    apiMock.get.mockResolvedValueOnce({ config })
    apiMock.get.mockResolvedValueOnce([sub])
    apiMock.post.mockResolvedValueOnce({ status: 'ok', imported: 10 })
    apiMock.get.mockResolvedValueOnce([sub])

    const w = mount(IpListView)
    await flushPromises()

    await w.findAll('button').find((b) => b.text() === '同步')!.trigger('click')
    await flushPromises()

    expect(apiMock.post).toHaveBeenCalledWith('/ip-list-subs/1/sync')
    expect(w.text()).toContain('同步完成，并入 10 条')
  })

  it('删除订阅源', async () => {
    apiMock.get.mockResolvedValueOnce({ config })
    apiMock.get.mockResolvedValueOnce([sub])
    apiMock.delete.mockResolvedValueOnce({ status: 'ok' })
    apiMock.get.mockResolvedValueOnce([])

    const w = mount(IpListView)
    await flushPromises()

    const delBtn = w.findAll('button').find((b) => (b.classes() || []).includes('text-destructive'))
    expect(delBtn).toBeTruthy()
    await delBtn!.trigger('click')
    await flushPromises()

    expect(apiMock.delete).toHaveBeenCalledWith('/ip-list-subs/1')
  })
})
