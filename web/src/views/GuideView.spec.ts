import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import GuideView from '@/views/GuideView.vue'

const apiMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
}))

vi.mock('@/api', () => ({ api: apiMock }))

const guide = {
  redis: { addr: '192.168.100.4:16379', password: '', db: 8 },
  install_command: 'curl -fsSL http://localhost/api/setup/install.sh | bash -s -- http://localhost -a 192.168.100.4:16379 -d 8',
  download_url: 'http://localhost/api/setup/waf.tar.gz',
  nginx_config: 'lua_package_path "/opt/waf/?.lua;;";\ninit_by_lua_file /opt/waf/init.lua;',
}

describe('GuideView 接入指引页', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('已配置 Redis 时展示安装命令与 nginx 配置', async () => {
    apiMock.get
      .mockResolvedValueOnce({ done: true, redis_configured: true, redis_addr: '192.168.100.4:16379' })
      .mockResolvedValueOnce(guide)

    const w = mount(GuideView)
    await flushPromises()

    expect(w.text()).toContain('接入指引')
    expect(w.text()).toContain('已配置')
    expect(w.text()).toContain('192.168.100.4:16379')
    expect(w.text()).toContain(guide.install_command)
    expect(w.text()).toContain('lua_package_path')
    // guide 请求需带 admin 参数
    expect(apiMock.get).toHaveBeenLastCalledWith(expect.stringContaining('/setup/guide?admin='))
  })

  it('未配置 Redis 时不请求 guide', async () => {
    apiMock.get.mockResolvedValueOnce({ done: false, redis_configured: false })

    const w = mount(GuideView)
    await flushPromises()

    expect(w.text()).toContain('未配置')
    expect(w.text()).toContain('请先在上方配置 Redis')
    expect(apiMock.get).toHaveBeenCalledTimes(1)
  })

  it('保存 Redis 后重新加载指引', async () => {
    apiMock.get
      .mockResolvedValueOnce({ done: false, redis_configured: false })
      .mockResolvedValueOnce({ done: true, redis_configured: true, redis_addr: '1.2.3.4:6379' })
      .mockResolvedValueOnce(guide)
    apiMock.post.mockResolvedValueOnce({ status: 'ok' })

    const w = mount(GuideView)
    await flushPromises()
    await w.find('button').trigger('click')
    await flushPromises()

    expect(apiMock.post).toHaveBeenCalledWith('/setup/redis', expect.any(Object))
    expect(w.text()).toContain('已保存并下发')
    expect(w.text()).toContain(guide.install_command)
  })

  it('保存 Redis 失败提示错误', async () => {
    apiMock.get.mockResolvedValueOnce({ done: false, redis_configured: false })
    apiMock.post.mockRejectedValueOnce(new Error('Redis 连接失败'))

    const w = mount(GuideView)
    await flushPromises()
    await w.find('button').trigger('click')
    await flushPromises()

    expect(w.text()).toContain('Redis 连接失败')
  })

  it('已配置时回显已保存的库号', async () => {
    apiMock.get
      .mockResolvedValueOnce({ done: true, redis_configured: true, redis_addr: '192.168.100.4:16379' })
      .mockResolvedValueOnce(guide)

    const w = mount(GuideView)
    await flushPromises()

    const dbInput = w.findAll('input').find((i) => (i.element as HTMLInputElement).type === 'number')
    expect(dbInput).toBeTruthy()
    expect((dbInput!.element as HTMLInputElement).value).toBe('8')
  })
})
