<script setup lang="ts">
import { h, onMounted, reactive, ref } from 'vue';
import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NPagination,
  NSelect,
  NSpace,
  NSwitch,
  NTabPane,
  NTabs,
  NTag
} from 'naive-ui';
import { consumeChallenges, fetchChallenges, fetchConfig, saveConfig } from '@/service/api';

const saving = ref(false);
const loaded = ref(false);
const challenge = reactive({
  enabled: true,
  mode: 'basic',
  cookie_ttl: 300,
  page_path: '/__waf_challenge__',
  verify_path: '/__waf_challenge_verify__',
  captcha: { id: '', key: '', verify_api: '', sdk: '' }
});
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
    captcha: { id: '', key: '', verify_api: '', sdk: '', ...((ch.captcha as Record<string, unknown>) ?? {}) }
  });
  loaded.value = true;
}

async function save() {
  saving.value = true;
  try {
    const next = {
      ...rawConfig,
      challenge: {
        enabled: challenge.enabled,
        mode: challenge.mode,
        cookie_ttl: challenge.cookie_ttl,
        page_path: challenge.page_path,
        verify_path: challenge.verify_path,
        captcha: challenge.captcha
      }
    };
    await saveConfig(next);
    window.$message?.success('人机验证配置已保存并下发，引擎 5 秒内热更新生效');
  } finally {
    saving.value = false;
  }
}

// ===== 验证记录 =====
const actionMeta: Record<string, { label: string; type: 'info' | 'success' | 'error' }> = {
  issue: { label: '下发挑战', type: 'info' },
  pass: { label: '验证通过', type: 'success' },
  fail: { label: '验证失败', type: 'error' }
};
const records = ref<Api.Waf.ChallengeItem[]>([]);
const recordTotal = ref(0);
const recordLoading = ref(false);
const recordQuery = reactive({ page: 1, page_size: 20, action: '' });

function fmtTime(t: string) {
  if (!t) return '-';
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '');
}
function geoText(e: Api.Waf.ChallengeItem) {
  return [e.country, e.province, e.city].filter(Boolean).join(' ');
}

async function loadRecords() {
  recordLoading.value = true;
  try {
    const res = await fetchChallenges({
      page: recordQuery.page,
      page_size: recordQuery.page_size,
      ...(recordQuery.action ? { action: recordQuery.action } : {})
    });
    records.value = res.data?.items ?? [];
    recordTotal.value = res.data?.total ?? 0;
  } finally {
    recordLoading.value = false;
  }
}

async function consumeRecord() {
  await consumeChallenges();
  window.$message?.success('已触发消费');
  await loadRecords();
}

const recordColumns = [
  { title: '时间', key: 'time', width: 150, render: (row: Api.Waf.ChallengeItem) => fmtTime(row.time) },
  {
    title: '来源',
    key: 'client_ip',
    minWidth: 160,
    render: (row: Api.Waf.ChallengeItem) =>
      h('div', { class: 'space-y-0.5' }, [
        h('div', { class: 'font-mono text-xs' }, row.client_ip),
        row.country
          ? h('div', { class: 'flex items-center gap-1 text-[11px] text-[rgb(125,125,125)]' }, [
              h('span', { class: 'inline-block h-1 w-1 rounded-full bg-[#60a5fa]' }),
              geoText(row)
            ])
          : null
      ])
  },
  {
    title: '动作',
    key: 'action',
    width: 110,
    render: (row: Api.Waf.ChallengeItem) =>
      h(NTag, { size: 'small', type: actionMeta[row.action]?.type || 'default', bordered: false }, { default: () => actionMeta[row.action]?.label || row.action })
  },
  { title: 'URI', key: 'uri', minWidth: 220, ellipsis: { tooltip: true }, render: (row: Api.Waf.ChallengeItem) => h('span', { class: 'font-mono text-xs' }, row.uri) }
];

onMounted(() => {
  load();
  loadRecords();
});
</script>

<template>
  <div class="space-y-4">
    <div>
      <h2 class="text-xl font-semibold">人机验证</h2>
      <p class="text-sm text-[rgb(125,125,125)]">配置验证方式与策略；哪些请求需要验证请在「触发规则」页配置人机验证触发规则</p>
    </div>

    <NTabs type="line" animated>
      <!-- 配置 -->
      <NTabPane name="config" tab="验证配置">
        <NCard :bordered="false" class="card-wrapper" v-if="loaded">
          <div class="mb-4 rounded-lg border border-[rgb(230,240,255)] bg-[rgb(245,250,255)] px-4 py-3 text-sm text-[rgb(70,90,130)]">
            💡 触发方式已统一由「触发规则」页管理：创建「人机验证」用途的触发规则（可按域名 / User-Agent / 请求头 / IP / 路径等条件筛选），
            命中后将先经过人机验证才可访问。
          </div>
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
      </NTabPane>

      <!-- 验证记录 -->
      <NTabPane name="records" tab="验证记录">
        <NCard :bordered="false" class="card-wrapper">
          <template #header-extra>
            <NSpace>
              <NSelect
                v-model:value="recordQuery.action"
                :options="[
                  { label: '全部', value: '' },
                  { label: '下发挑战', value: 'issue' },
                  { label: '验证通过', value: 'pass' },
                  { label: '验证失败', value: 'fail' }
                ]"
                class="w-32"
                @update:value="recordQuery.page = 1; loadRecords()"
              />
              <NButton size="small" secondary @click="consumeRecord">消费队列</NButton>
            </NSpace>
          </template>
          <NDataTable :columns="recordColumns" :data="records" :loading="recordLoading" :bordered="false" size="small" />
          <div class="mt-4 flex justify-end">
            <NPagination v-model:page="recordQuery.page" :page-size="recordQuery.page_size" :item-count="recordTotal" @update:page="loadRecords" />
          </div>
        </NCard>
      </NTabPane>
    </NTabs>
  </div>
</template>
