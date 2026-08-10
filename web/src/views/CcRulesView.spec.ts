import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import CcRulesView from '@/views/CcRulesView.vue'

const apiMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn(),
}))

vi.mock('@/api', () => ({ api: apiMock }))

const ruleA = {
  id: 1,
  name: '全局限流',
  host: '',
  path: '',
  rate: '100/60',
  ban_duration: 300,
  enabled: true,
  sort_order: 0,
}
const ruleB = {
  id: 2,
  name: 'API 限流',
  host: 'api.example.com',
  path: '/v1',
  rate: '30/60',
  ban_duration: 600,
  enabled: false,
  sort_order: 1,
}

describe('CcRulesView CC 防刷页', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.stubGlobal('confirm', vi.fn(() => true))
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('加载并渲染规则列表', async () => {
    apiMock.get.mockResolvedValueOnce([ruleA, ruleB])
    const w = mount(CcRulesView)
    await flushPromises()

    expect(apiMock.get).toHaveBeenCalledWith('/cc-rules')
    expect(w.text()).toContain('全局限流')
    expect(w.text()).toContain('api.example.com')
    expect(w.text()).toContain('30/60')
    expect(w.text()).toContain('停用') // ruleB 停用
  })

  it('新增规则并保存', async () => {
    apiMock.get.mockResolvedValueOnce([])
    apiMock.post.mockResolvedValueOnce({ id: 3 })
    apiMock.get.mockResolvedValueOnce([{ ...ruleA, name: '新规则' }])

    const w = mount(CcRulesView)
    await flushPromises()

    const inputs = w.findAll('input')
    // 名称、域名、路径、频率、封禁、排序 + 启用 checkbox
    await inputs[0].setValue('新规则')
    await inputs[1].setValue('admin.example.com')
    await inputs[3].setValue('50/60')

    await w.findAll('button').find((b) => b.text() === '添加规则')!.trigger('click')
    await flushPromises()

    expect(apiMock.post).toHaveBeenCalledWith('/cc-rules', expect.objectContaining({
      name: '新规则',
      host: 'admin.example.com',
      rate: '50/60',
    }))
    expect(w.text()).toContain('新规则')
  })

  it('发布规则触发热更新', async () => {
    apiMock.get.mockResolvedValueOnce([ruleA])
    apiMock.post.mockResolvedValueOnce({ status: 'ok', rule_count: 1 })

    const w = mount(CcRulesView)
    await flushPromises()

    await w.findAll('button').find((b) => b.text().includes('发布并热更新'))!.trigger('click')
    await flushPromises()

    expect(apiMock.post).toHaveBeenCalledWith('/cc-rules/publish')
    expect(w.text()).toContain('已发布 1 条规则')
  })

  it('启停与删除规则', async () => {
    apiMock.get.mockResolvedValueOnce([ruleA])
    apiMock.patch.mockResolvedValueOnce({ status: 'ok' })
    apiMock.get.mockResolvedValueOnce([{ ...ruleA, enabled: false }])
    apiMock.delete.mockResolvedValueOnce({ status: 'ok' })
    apiMock.get.mockResolvedValueOnce([])

    const w = mount(CcRulesView)
    await flushPromises()

    // 停用
    await w.findAll('button').find((b) => b.text() === '停用')!.trigger('click')
    await flushPromises()
    expect(apiMock.patch).toHaveBeenCalledWith('/cc-rules/1/enabled', { enabled: false })

    // 删除（confirm 已 stub 为 true；用 text-destructive 定位删除按钮）
    const delBtn = w.findAll('button').find((b) => (b.classes() || []).includes('text-destructive'))
    expect(delBtn).toBeTruthy()
    await delBtn!.trigger('click')
    await flushPromises()
    expect(apiMock.delete).toHaveBeenCalledWith('/cc-rules/1')
  })
})
