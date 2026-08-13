<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { NAlert, NButton, NCard, NForm, NFormItem, NInputNumber, NSpace, NSwitch } from 'naive-ui';
import { fetchConfig, saveConfig } from '@/service/api';

const saving = ref(false);
const loaded = ref(false);
const ccEnabled = ref(true);
const cc = reactive({ rate_count: 100, rate_seconds: 60, ban_duration: 300 });
let rawConfig: Record<string, unknown> = {};

const ratePreview = computed(() => `每 ${cc.rate_seconds} 秒内，同一 IP 同一路径最多允许 ${cc.rate_count} 次请求，超出后封禁该 IP ${cc.ban_duration} 秒`);

async function load() {
  const res = await fetchConfig();
  rawConfig = res.data?.config ?? {};
  const c = (rawConfig.cc as Record<string, unknown>) ?? {};
  const m = String(c.rate || '100/60').match(/^(\d+)\/(\d+)$/);
  cc.rate_count = m ? Number(m[1]) : 100;
  cc.rate_seconds = m ? Number(m[2]) : 60;
  cc.ban_duration = Number(c.ban_duration) || 300;
  ccEnabled.value = ((rawConfig.modules as Record<string, unknown>)?.cc_check) !== false;
  loaded.value = true;
}

async function save() {
  saving.value = true;
  try {
    const next = {
      ...rawConfig,
      modules: { ...((rawConfig.modules as Record<string, unknown>) ?? {}), cc_check: ccEnabled.value },
      cc: { ...((rawConfig.cc as Record<string, unknown>) ?? {}), rate: `${cc.rate_count}/${cc.rate_seconds}`, ban_duration: cc.ban_duration }
    };
    await saveConfig(next);
    window.$message?.success('CC 限流策略已保存并下发，引擎 5 秒内热更新生效');
  } finally {
    saving.value = false;
  }
}

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <div>
      <h2 class="text-xl font-semibold">CC 限流</h2>
      <p class="text-sm text-[rgb(125,125,125)]">配置全局频率限制策略；哪些请求参与限流请在「触发规则」页配置 CC 触发规则</p>
    </div>

    <NCard :bordered="false" class="card-wrapper" v-if="loaded">
      <div class="mb-4 rounded-lg border border-[rgb(230,240,255)] bg-[rgb(245,250,255)] px-4 py-3 text-sm text-[rgb(70,90,130)]">
        💡 限流对象已统一由「触发规则」页管理：创建「CC 限流」用途的触发规则（可按域名 / User-Agent / 请求头 / IP / 路径等条件筛选），
        命中的请求将参与本页配置的频率限制，超限自动封禁 IP。
      </div>

      <NForm label-placement="left" label-width="150">
        <NFormItem label="启用 CC 限流">
          <NSwitch v-model:value="ccEnabled" />
        </NFormItem>

        <NFormItem label="频率限制">
          <NSpace align="center" :wrap="true">
            <span class="text-sm text-[rgb(125,125,125)]">每</span>
            <NInputNumber v-model:value="cc.rate_seconds" :min="1" class="w-24" />
            <span class="text-sm text-[rgb(125,125,125)]">秒内，同一 IP 同一路径最多</span>
            <NInputNumber v-model:value="cc.rate_count" :min="1" class="w-28" />
            <span class="text-sm text-[rgb(125,125,125)]">次</span>
          </NSpace>
        </NFormItem>

        <NFormItem label="封禁时长(s)">
          <NInputNumber v-model:value="cc.ban_duration" :min="1" class="w-32" />
          <span class="ml-2 text-xs text-[rgb(125,125,125)]">超限后封禁该 IP 的秒数，封禁期内所有路径均被拦截</span>
        </NFormItem>

        <NFormItem label=" ">
          <div class="w-full rounded bg-[rgb(245,245,245)] px-3 py-2 text-xs">
            <span class="text-[rgb(125,125,125)]">策略预览：</span>
            <span class="text-[rgb(60,60,60)]">{{ ratePreview }}</span>
          </div>
        </NFormItem>

        <NFormItem label=" ">
          <NButton type="primary" :loading="saving" @click="save">保存策略</NButton>
        </NFormItem>
      </NForm>
    </NCard>
  </div>
</template>
