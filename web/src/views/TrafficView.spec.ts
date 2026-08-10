import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import TrafficView from '@/views/TrafficView.vue'

const apiMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
}))

vi.mock('@/api', () => ({ api: apiMock }))

const config = { mode: 'active', traffic_log: { enabled: false, retention_days: 7 } }
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
      uri: '/?id=1',
      status: 200,
      user_agent: 'curl',
      attack: false,
      rule_ids: '',
      response_time: 12.5,
    },
  ],
}
const stats = { total: 1, attack: 0 }

describe('TrafficView 流量日志页', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('加载配置、统计与列表', async () => {
    apiMock.get.mockResolvedValueOnce({ config })
    apiMock.get.mockResolvedValueOnce(stats)
    apiMock.get.mockResolvedValueOnce(pageResult)

    const w = mount(TrafficView)
    await flushPromises()

    expect(apiMock.get).toHaveBeenCalledWith('/traffic/stats')
    expect(apiMock.get).toHaveBeenCalledWith(expect.stringContaining('/traffic?'))
    expect(w.text()).toContain('a.example.com')
    expect(w.text()).toContain('正常')
  })

  it('保存全量记录配置', async () => {
    apiMock.get.mockResolvedValueOnce({ config })
    apiMock.get.mockResolvedValueOnce(stats)
    apiMock.get.mockResolvedValueOnce(pageResult)
    apiMock.put.mockResolvedValueOnce({ status: 'ok' })

    const w = mount(TrafficView)
    await flushPromises()

    const chk = w.find('input[type="checkbox"]')
    await chk.setValue(true)
    await w.findAll('button').find((b) => b.text() === '保存配置')!.trigger('click')
    await flushPromises()

    expect(apiMock.put).toHaveBeenCalledWith('/config', expect.objectContaining({
      config: expect.objectContaining({
        traffic_log: expect.objectContaining({ enabled: true }),
      }),
    }))
    expect(w.text()).toContain('已保存并下发')
  })

  it('立即清理过期记录', async () => {
    apiMock.get.mockResolvedValueOnce({ config })
    apiMock.get.mockResolvedValueOnce(stats)
    apiMock.get.mockResolvedValueOnce(pageResult)
    apiMock.post.mockResolvedValueOnce({ status: 'ok', deleted: 5 })
    apiMock.get.mockResolvedValueOnce(stats)
    apiMock.get.mockResolvedValueOnce(pageResult)

    const w = mount(TrafficView)
    await flushPromises()

    await w.findAll('button').find((b) => b.text() === '立即清理过期记录')!.trigger('click')
    await flushPromises()

    expect(apiMock.post).toHaveBeenCalledWith('/traffic/cleanup?days=7')
    expect(w.text()).toContain('已清理 5 条超过 7 天的记录')
  })
})
