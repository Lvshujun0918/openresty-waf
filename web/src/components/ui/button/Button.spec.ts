import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import Button from '@/components/ui/button/Button.vue'

describe('Button 组件', () => {
  it('渲染为 button 元素与默认插槽', () => {
    const w = mount(Button, { slots: { default: '提交' } })
    expect(w.element.tagName).toBe('BUTTON')
    expect(w.text()).toBe('提交')
  })

  it('默认 variant/size 基础样式', () => {
    const w = mount(Button, { slots: { default: 'x' } })
    expect(w.element.className).toContain('bg-primary')
    expect(w.element.className).toContain('h-9')
  })

  it('variant=destructive 应用红色样式', () => {
    const w = mount(Button, { props: { variant: 'destructive' }, slots: { default: '删除' } })
    expect(w.element.className).toContain('bg-destructive')
  })

  it('variant=outline 应用描边样式', () => {
    const w = mount(Button, { props: { variant: 'outline' }, slots: { default: 'x' } })
    expect(w.element.className).toContain('border-input')
  })

  it('size=sm 应用小尺寸', () => {
    const w = mount(Button, { props: { size: 'sm' }, slots: { default: 'x' } })
    expect(w.element.className).toContain('h-8')
  })

  it('size=lg 应用大尺寸', () => {
    const w = mount(Button, { props: { size: 'lg' }, slots: { default: 'x' } })
    expect(w.element.className).toContain('h-10')
  })

  it('class prop 合并', () => {
    const w = mount(Button, { props: { class: 'extra-class' }, slots: { default: 'x' } })
    expect(w.element.className).toContain('extra-class')
  })

  it('点击事件冒泡', async () => {
    const w = mount(Button, { slots: { default: 'x' } })
    await w.trigger('click')
    expect(w.emitted('click')).toBeTruthy()
  })
})
