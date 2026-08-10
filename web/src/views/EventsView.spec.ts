import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import EventsView from '@/views/EventsView.vue'

const apiMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
}))

vi.mock('@/api', () => ({ api: apiMock }))

const pageResult = {
  total: 1,
  page: 1,
  page_size: 20,
  items: [
    {
      id: 1,
      time: '2026-08-10T10:00:00Z',
      client_ip: '1.2.3.4',
      method: 'GET',
      host: 'a.example.com',
      uri: '/?id=1 union select 1',
      rule_id: '20001',
      group: 'sqli',
      msg: 'SQL 注入：union select',
      severity: 3,
      status: 403,
    },
  ],
}

describe('EventsView 攻击事件页', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('进入页面自动消费 Redis 队列再加载列表', async () => {
    apiMock.post.mockResolvedValueOnce({ status: 'ok', consumed: 1 })
    apiMock.get.mockResolvedValueOnce(pageResult)

    const w = mount(EventsView)
    await flushPromises()

    expect(apiMock.post).toHaveBeenCalledWith('/events/consume')
    expect(apiMock.get).toHaveBeenCalledWith(expect.stringContaining('/events?'))
    expect(w.text()).toContain('1.2.3.4')
    expect(w.text()).toContain('SQL 注入')
  })

  it('自动消费失败时仍加载列表', async () => {
    apiMock.post.mockRejectedValueOnce(new Error('Redis 未配置'))
    apiMock.get.mockResolvedValueOnce(pageResult)

    const w = mount(EventsView)
    await flushPromises()

    expect(apiMock.get).toHaveBeenCalled()
    expect(w.text()).toContain('1.2.3.4')
  })

  it('显示域名列', async () => {
    apiMock.post.mockResolvedValueOnce({ status: 'ok', consumed: 0 })
    apiMock.get.mockResolvedValueOnce(pageResult)

    const w = mount(EventsView)
    await flushPromises()

    expect(w.text()).toContain('a.example.com')
  })

  it('按域名过滤查询', async () => {
    apiMock.post.mockResolvedValue({ status: 'ok', consumed: 0 })
    // onMounted 自动消费 + 点击查询都会调用 load，用持续返回值
    apiMock.get.mockResolvedValue(pageResult)

    const w = mount(EventsView)
    await flushPromises()

    const hostInput = w.findAll('input').find((i) => (i.element as HTMLInputElement).placeholder.includes('example.com'))
    expect(hostInput).toBeTruthy()
    await hostInput!.setValue('a.example.com')
    await w.findAll('button').find((b) => b.text() === '查询')!.trigger('click')
    await flushPromises()

    expect(apiMock.get).toHaveBeenLastCalledWith(expect.stringContaining('host=a.example.com'))
  })

  it('手动点击消费按钮触发消费', async () => {
    apiMock.post.mockResolvedValue({ status: 'ok', consumed: 0 })
    // onMounted 自动消费 + 点击后再次消费都会调用 load，用持续返回值
    apiMock.get.mockResolvedValue(pageResult)

    const w = mount(EventsView)
    await flushPromises()
    apiMock.post.mockClear()

    const btn = w.findAll('button').find((b) => b.text().includes('消费'))
    expect(btn).toBeTruthy()
    await btn!.trigger('click')
    await flushPromises()

    expect(apiMock.post).toHaveBeenCalledWith('/events/consume')
  })
})
