import { describe, it, expect } from 'vitest'
import { cn } from '@/lib/utils'

describe('cn（类名合并工具）', () => {
  it('合并多个类名', () => {
    expect(cn('a', 'b', 'c')).toBe('a b c')
  })

  it('过滤假值参数', () => {
    expect(cn('a', undefined, null, false, '', 'b')).toBe('a b')
  })

  it('tailwind 冲突类名后者覆盖前者', () => {
    expect(cn('px-2', 'px-4')).toBe('px-4')
    expect(cn('text-red-500', 'text-blue-500')).toBe('text-blue-500')
  })

  it('支持条件对象', () => {
    expect(cn({ 'text-red-500': true, 'text-blue-500': false })).toBe('text-red-500')
  })

  it('混合数组与条件', () => {
    expect(cn(['a', 'b'], { c: true }, 'd')).toBe('a b c d')
  })

  it('空参数返回空串', () => {
    expect(cn()).toBe('')
  })
})
