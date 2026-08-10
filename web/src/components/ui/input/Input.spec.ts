import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import Input from '@/components/ui/input/Input.vue'

describe('Input 组件', () => {
  it('渲染 modelValue 为输入值', () => {
    const w = mount(Input, { props: { modelValue: 'hello' } })
    expect((w.element as HTMLInputElement).value).toBe('hello')
  })

  it('空 modelValue 显示为空', () => {
    const w = mount(Input, { props: { modelValue: '' } })
    expect((w.element as HTMLInputElement).value).toBe('')
  })

  it('输入触发 update:modelValue 事件', async () => {
    const w = mount(Input, { props: { modelValue: '' } })
    await w.setValue('abc')
    const emitted = w.emitted('update:modelValue')
    expect(emitted).toBeTruthy()
    expect(emitted![0]).toEqual(['abc'])
  })

  it('数字 modelValue 正常显示', () => {
    const w = mount(Input, { props: { modelValue: 42 } })
    expect((w.element as HTMLInputElement).value).toBe('42')
  })

  it('class prop 应用到元素', () => {
    const w = mount(Input, { props: { modelValue: '', class: 'my-custom-class' } })
    expect((w.element as HTMLElement).className).toContain('my-custom-class')
  })

  it('支持 v-model 双向绑定', async () => {
    const w = mount(
      {
        components: { Input },
        template: '<Input v-model="v" />',
        data: () => ({ v: '初始值' }),
      },
      {},
    )
    expect((w.find('input').element as HTMLInputElement).value).toBe('初始值')
    await w.find('input').setValue('新值')
    expect(w.vm.v).toBe('新值')
  })
})
