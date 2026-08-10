<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { api } from '@/api'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Fingerprint } from 'lucide-vue-next'

const cfg = reactive<any>({
  challenge: { captcha: {} },
})
const loading = ref(true)
const saving = ref(false)
const msg = ref('')
const error = ref('')

async function load() {
  loading.value = true
  error.value = ''
  try {
    const d = await api.get<{ config: any }>('/config')
    Object.assign(cfg, d.config || {})
    cfg.challenge = cfg.challenge || {}
    cfg.challenge.captcha = cfg.challenge.captcha || {}
  } catch (e: any) {
    error.value = e.message || '配置加载失败'
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  msg.value = ''
  error.value = ''
  try {
    await api.put('/config', { config: cfg })
    msg.value = '已保存并下发，引擎将在数秒内热更新生效'
  } catch (e: any) {
    error.value = e.message || '保存失败'
  } finally {
    saving.value = false
  }
  setTimeout(() => (msg.value = ''), 4000)
}

onMounted(load)
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-semibold flex items-center gap-2">
          <Fingerprint class="h-6 w-6" /> 人机验证
        </h1>
        <p class="text-sm text-muted-foreground">
          在 CC 超限或需要验证时展示验证页，通过后放行；basic 自包含，geetest/gitee 需配置凭证
        </p>
      </div>
      <Button :disabled="saving || loading" @click="save">{{ saving ? '保存中…' : '保存并下发' }}</Button>
    </div>

    <div v-if="!loading" class="grid gap-4 lg:grid-cols-2">
      <!-- 基本 -->
      <Card>
        <CardHeader>
          <CardTitle>验证策略</CardTitle>
          <CardDescription>触发时机与放行规则</CardDescription>
        </CardHeader>
        <CardContent class="space-y-4">
          <label class="flex items-center gap-2 text-sm">
            <input v-model="cfg.challenge.enabled" type="checkbox" class="h-4 w-4" /> 启用人机验证
          </label>
          <div class="grid grid-cols-2 gap-4">
            <div class="space-y-1.5">
              <Label>模式</Label>
              <select v-model="cfg.challenge.mode" class="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm">
                <option value="basic">basic · 基础 JS 验证</option>
                <option value="geetest">geetest · 极验 GT4</option>
                <option value="gitee">gitee · Gitee 验证码</option>
              </select>
            </div>
            <div class="space-y-1.5">
              <Label>放行时长（秒）</Label>
              <Input v-model.number="cfg.challenge.cookie_ttl" type="number" />
            </div>
          </div>
          <div class="space-y-1.5">
            <Label>Cookie 名称</Label>
            <Input v-model="cfg.challenge.cookie_name" />
          </div>
          <div class="space-y-1.5">
            <Label>签名密钥（生产环境务必修改）</Label>
            <Input v-model="cfg.challenge.cookie_secret" />
          </div>
        </CardContent>
      </Card>

      <!-- 路径与高级 -->
      <Card>
        <CardHeader>
          <CardTitle>验证路径与高级凭证</CardTitle>
          <CardDescription>geetest / gitee 模式需配置以下凭证</CardDescription>
        </CardHeader>
        <CardContent class="space-y-4">
          <div class="grid grid-cols-2 gap-4">
            <div class="space-y-1.5">
              <Label>验证页路径</Label>
              <Input v-model="cfg.challenge.page_path" />
            </div>
            <div class="space-y-1.5">
              <Label>回调路径</Label>
              <Input v-model="cfg.challenge.verify_path" />
            </div>
          </div>
          <div class="grid grid-cols-2 gap-4">
            <div class="space-y-1.5">
              <Label>captcha_id</Label>
              <Input v-model="cfg.challenge.captcha.id" placeholder="高级模式" />
            </div>
            <div class="space-y-1.5">
              <Label>captcha_key</Label>
              <Input v-model="cfg.challenge.captcha.key" type="password" placeholder="高级模式" />
            </div>
          </div>
          <div class="space-y-1.5">
            <Label>验证接口（可选）</Label>
            <Input v-model="cfg.challenge.captcha.verify_api" />
          </div>
          <div class="space-y-1.5">
            <Label>SDK 地址（可选）</Label>
            <Input v-model="cfg.challenge.captcha.sdk" />
          </div>
          <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
          <p v-if="msg" class="text-sm text-primary">{{ msg }}</p>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
