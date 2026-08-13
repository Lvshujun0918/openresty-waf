import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import RulesView from '@/views/RulesView.vue'

const apiMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn(),
}))

vi.mock('@/api', () => ({ api: apiMock }))

const rule = {
  id: 1,
  rule_id: '90001',
  name: '测试规则',
  group: 'custom',
  phase: 'access',
  severity: 2,
  enabled: true,
  operator: 'REGEX',
  pattern: 'union\\s+select',
  transforms: '["url_decode","to_lowercase"]',
  vars: '[{"type":"URI_ARGS"},{"type":"POST_ARGS"}]',
  status: 403,
  message: 'x',
}

describe('RulesView 规则管理（友好表单）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('加载并渲染规则列表', async () => {
    apiMock.get.mockResolvedValueOnce([rule])
    const w = mount(RulesView)
    await flushPromises()
    expect(apiMock.get).toHaveBeenCalledWith('/rules')
    expect(w.text()).toContain('测试规则')
    expect(w.text()).toContain('90001')
  })

  it('新增规则：友好表单映射为 DSL 字段', async () => {
    apiMock.get.mockResolvedValueOnce([])
    apiMock.post.mockResolvedValueOnce({})
    apiMock.get.mockResolvedValueOnce([])

    const w = mount(RulesView)
    await flushPromises()
    await w.findAll('button').find((b) => b.text() === '新增规则')!.trigger('click')
    await flushPromises()

    // 填名称（按 placeholder 定位规则名称输入框）与匹配值（textarea）
    const nameInput = w.findAll('input').find((i) =>
      (i.element as HTMLInputElement).placeholder?.includes('拦截'),
    )!
    await nameInput.setValue('拦截 admin')
    await w.find('textarea').setValue('admin/login')
    await w.findAll('button').find((b) => b.text() === '保存规则')!.trigger('click')
    await flushPromises()

    const [, payload] = apiMock.post.mock.calls[0]
    expect(payload.operator).toBe('CONTAINS')
    expect(payload.pattern).toBe('admin/login')
    expect(payload.name).toBe('拦截 admin')
    // transforms / vars 为合法 JSON 且包含预期内容
    expect(payload.transforms).toContain('url_decode')
    expect(payload.vars).toContain('URI_ARGS')
    expect(JSON.parse(payload.actions).disrupt).toBe('BLOCK')
    expect(JSON.parse(payload.actions).status).toBe(403)
    // rule_id 自动生成
    expect(payload.rule_id).toMatch(/^9\d+$/)
  })

  it('新增语义检测规则时无需匹配值', async () => {
    apiMock.get.mockResolvedValueOnce([])
    apiMock.post.mockResolvedValueOnce({})
    apiMock.get.mockResolvedValueOnce([])

    const w = mount(RulesView)
    await flushPromises()
    await w.findAll('button').find((b) => b.text() === '新增规则')!.trigger('click')
    await flushPromises()

    // 匹配方式选 SQL 注入语义检测
    const matchSelect = w.findAll('select').find((s) =>
      [...s.element.options].some((o) => o.value === 'LIBINJECTION_SQLI'),
    )!
    await matchSelect.setValue('LIBINJECTION_SQLI')
    await w.findAll('button').find((b) => b.text() === '保存规则')!.trigger('click')
    await flushPromises()

    const [, payload] = apiMock.post.mock.calls[0]
    expect(payload.operator).toBe('LIBINJECTION_SQLI')
    expect(payload.pattern).toBe('')
  })

  it('编辑规则：DSL 回显到友好表单', async () => {
    apiMock.get.mockResolvedValueOnce([rule])
    const w = mount(RulesView)
    await flushPromises()

    await w.findAll('button').find((b) => b.text() === '编辑')!.trigger('click')
    await flushPromises()

    const matchSelect = w.findAll('select').find((s) =>
      [...s.element.options].some((o) => o.value === 'REGEX'),
    )!
    expect((matchSelect.element as HTMLSelectElement).value).toBe('REGEX')
    expect((w.find('textarea').element as HTMLTextAreaElement).value).toContain('union')
  })
})
