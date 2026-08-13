<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { NButton, NCard, NForm, NFormItem, NInput, NInputNumber, NSpace, NSwitch, NTag } from 'naive-ui';
import { fetchConfig, saveConfig } from '@/service/api';

const saving = ref(false);
const loaded = ref(false);
const challenge = reactive({
  enabled: true,
  mode: 'basic',
  cookie_ttl: 300,
  page_path: '/__waf_challenge__',
  verify_path: '/__waf_challenge_verify__',
  trigger_paths: [] as string[],
  captcha: { id: '', key: '', verify_api: '', sdk: '' }
});
const triggerText = ref('');
let rawConfig: Record<string, unknown> = {};

async function load() {
  const res = await fetchConfig();
  rawConfig = res.data?.config ?? {};
  const ch = (rawConfig.challenge as Record<string, unknown>) ?? {};
  Object.assign(challenge, {
    enabled: ch.enabled !== false,
    mode: ch.mode || 'basic',
    cookie_ttl: Number(ch.cookie_ttl) || 300,
    page_path: ch.page_path || '/__waf_challenge__',
    verify_path: ch.verify_path || '/__waf_challenge_verify__',
    trigger_paths: Array.isArray(ch.trigger_paths) ? (ch.trigger_paths as string[]) : [],
    captcha: { id: '', key: '', verify_api: '', sdk: '', ...((ch.captcha as Record<string, unknown>) ?? {}) }
  });
  triggerText.value = challenge.trigger_paths.join('\n');
  loaded.value = true;
}

async function save() {
  saving.value = true;
  try {
    const triggerPaths = triggerText.value
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);
    const next = {
      ...rawConfig,
      challenge: {
        enabled: challenge.enabled,
        mode: challenge.mode,
        cookie_ttl: challenge.cookie_ttl,
        page_path: challenge.page_path,
        verify_path: challenge.verify_path,
        trigger_paths: triggerPaths,
        captcha: challenge.captcha
      }
    };
    await saveConfig(next);
    window.$message?.success('人机验证配置已保存并下发，引擎 5 秒内热更新生效');
  } finally {
    saving.value = false;
  }
}

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <div>
      <h2 class="text-xl font-semibold">人机验证</h2>
      <p class="text-sm text-[rgb(125,125,125)]">通过 JS 挑战 / 验证码拦截自动化攻击，支持配置路径手动触发</p>
    </div>

    <NCard :bordered="false" class="card-wrapper" v-if="loaded">
      <NForm label-placement="left" label-width="140">
        <NFormItem label="启用">
          <NSwitch v-model:value="challenge.enabled" />
        </NFormItem>
        <NFormItem label="验证模式">
          <NSpace align="center">
            <NTag :type="challenge.mode === 'basic' ? 'primary' : 'default'" bordered>basic（JS/Cookie 挑战）</NTag>
            <NTag :type="challenge.mode === 'geetest' ? 'primary' : 'default'" bordered>geetest（极验验证码）</NTag>
          </NSpace>
        </NFormItem>
        <NFormItem label="Cookie 有效期(s)">
          <NInputNumber v-model:value="challenge.cookie_ttl" :min="30" />
        </NFormItem>
        <NFormItem label="验证页路径">
          <NInput v-model:value="challenge.page_path" />
        </NFormItem>
        <NFormItem label="校验回调路径">
          <NInput v-model:value="challenge.verify_path" />
        </NFormItem>
        <NFormItem label="手动触发路径">
          <div class="w-full">
            <NInput v-model:value="triggerText" type="textarea" :rows="3" placeholder="每行一个前缀路径，如 /login、/api/user（留空则不手动触发）" />
            <p class="mt-1 text-xs text-[rgb(125,125,125)]">命中这些前缀的请求需先通过人机验证才可访问</p>
          </div>
        </NFormItem>
        <NFormItem label="极验 Captcha ID">
          <NInput v-model:value="challenge.captcha.id" placeholder="geetest 模式下填写" />
        </NFormItem>
        <NFormItem label="极验 Captcha Key">
          <NInput v-model:value="challenge.captcha.key" placeholder="geetest 模式下填写" />
        </NFormItem>
        <NFormItem>
          <NButton type="primary" :loading="saving" @click="save">保存配置</NButton>
        </NFormItem>
      </NForm>
    </NCard>
  </div>
</template>
