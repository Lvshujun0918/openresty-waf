<script setup lang="ts">
import { h, onMounted, reactive, ref } from 'vue';
import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInputNumber,
  NPagination,
  NSelect,
  NSpace,
  NStatistic,
  NSwitch,
  NTag
} from 'naive-ui';
import { cleanupTraffic, fetchConfig, fetchTraffic, fetchTrafficStats, saveConfig } from '@/service/api';

const items = ref<Api.Waf.TrafficItem[]>([]);
const total = ref(0);
const stats = ref({ total: 0, attack: 0 });
const loading = ref(false);
const saving = ref(false);
const message = ref('');

const cfg = reactive({
  traffic_log: { enabled: false, retention_days: 7 },
  config: {} as Record<string, unknown>
});

const query = reactive({ page: 1, page_size: 20, host: '', client_ip: '', attack: '' });

function fmtTime(t: string) {
  if (!t) return '-';
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '');
}
function geoText(e: Api.Waf.TrafficItem) {
  return [e.country, e.province, e.city].filter(Boolean).join(' ');
}

async function loadCfg() {
  const res = await fetchConfig();
  cfg.config = res.data?.config ?? {};
  const tl = (res.data?.config?.traffic_log as Record<string, unknown>) ?? {};
  cfg.traffic_log = { enabled: Boolean(tl.enabled), retention_days: Number(tl.retention_days) || 7 };
}

async function saveCfg() {
  saving.value = true;
  try {
    await saveConfig({ ...cfg.config, traffic_log: cfg.traffic_log });
    message.value = '全量记录配置已保存并下发，引擎将在数秒内热更新生效';
    window.$message?.success(message.value);
  } catch (e) {
    window.$message?.error(String(e));
  } finally {
    saving.value = false;
  }
}

async function loadStats() {
  const res = await fetchTrafficStats();
  stats.value = res.data ?? { total: 0, attack: 0 };
}

async function load() {
  loading.value = true;
  try {
    const res = await fetchTraffic({
      page: query.page,
      page_size: query.page_size,
      ...(query.host ? { host: query.host } : {}),
      ...(query.client_ip ? { client_ip: query.client_ip } : {}),
      ...(query.attack ? { attack: query.attack } : {})
    });
    items.value = res.data?.items ?? [];
    total.value = res.data?.total ?? 0;
  } finally {
    loading.value = false;
  }
}

async function cleanup() {
  const days = Number(cfg.traffic_log.retention_days) || 7;
  const res = await cleanupTraffic(days);
  window.$message?.success(`已清理 ${res.data?.deleted ?? 0} 条超过 ${days} 天的记录`);
  await Promise.all([loadStats(), load()]);
}

const columns = [
  { title: '时间', key: 'time', width: 150, render: (row: Api.Waf.TrafficItem) => fmtTime(row.time) },
  { title: '域名', key: 'host', width: 140, ellipsis: { tooltip: true }, render: (row: Api.Waf.TrafficItem) => row.host || '-' },
  {
    title: 'IP',
    key: 'client_ip',
    minWidth: 140,
    render: (row: Api.Waf.TrafficItem) =>
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
    title: '方法',
    key: 'method',
    width: 76,
    render: (row: Api.Waf.TrafficItem) =>
      h('span', { class: 'rounded border border-[rgb(229,229,229)] px-1.5 py-0.5 font-mono text-[11px]' }, row.method || '-')
  },
  { title: 'URI', key: 'uri', minWidth: 200, ellipsis: { tooltip: true }, render: (row: Api.Waf.TrafficItem) => h('span', { class: 'font-mono text-xs' }, row.uri) },
  {
    title: '状态',
    key: 'status',
    width: 70,
    render: (row: Api.Waf.TrafficItem) =>
      h(NTag, { size: 'small', type: row.status >= 400 ? 'error' : 'default', bordered: false }, { default: () => row.status })
  },
  {
    title: '攻击',
    key: 'attack',
    width: 70,
    render: (row: Api.Waf.TrafficItem) =>
      row.attack
        ? h(NTag, { size: 'small', type: 'error', bordered: false }, { default: () => '攻击' })
        : h('span', { class: 'text-xs text-[rgb(125,125,125)]' }, '正常')
  },
  { title: '耗时(ms)', key: 'response_time', width: 90, render: (row: Api.Waf.TrafficItem) => Math.round(row.response_time) }
];

onMounted(async () => {
  await Promise.all([loadCfg(), loadStats(), load()]);
});
</script>

<template>
  <div class="space-y-4">
    <div>
      <h2 class="text-xl font-semibold">流量日志</h2>
      <p class="text-sm text-[rgb(125,125,125)]">全量记录模式下记录每个请求；自动按保留天数清理过期数据</p>
    </div>

    <!-- 全量记录模式配置 -->
    <NCard :bordered="false" class="card-wrapper" title="全量记录模式">
      <template #header-extra>
        <NSpace>
          <NButton type="primary" secondary :loading="saving" @click="saveCfg">保存配置</NButton>
          <NButton secondary @click="cleanup">立即清理过期记录</NButton>
        </NSpace>
      </template>
      <div class="flex flex-wrap items-center gap-6">
        <NSpace align="center">
          <NSwitch v-model:value="cfg.traffic_log.enabled" />
          <span class="text-sm">开启全量记录</span>
        </NSpace>
        <div class="flex items-center gap-2">
          <span class="text-sm text-[rgb(125,125,125)]">保留天数（自动清理）</span>
          <NInputNumber v-model:value="cfg.traffic_log.retention_days" :min="1" class="w-24" />
        </div>
      </div>
    </NCard>

    <!-- 统计 + 过滤 -->
    <div class="grid grid-cols-1 gap-4 md:grid-cols-3">
      <NCard :bordered="false" class="card-wrapper">
        <NStatistic label="总记录数" :value="stats.total" />
      </NCard>
      <NCard :bordered="false" class="card-wrapper">
        <NStatistic label="命中攻击" :value="stats.attack">
          <template #suffix><span class="text-xs text-[rgb(239,68,68)]">条</span></template>
        </NStatistic>
      </NCard>
      <NCard :bordered="false" class="card-wrapper">
        <NForm inline label-placement="left" :show-feedback="false">
          <NFormItem label="域名">
            <NInput v-model:value="query.host" placeholder="如 example.com" class="w-32" clearable />
          </NFormItem>
          <NFormItem label="IP">
            <NInput v-model:value="query.client_ip" placeholder="如 1.2.3.4" class="w-32" clearable />
          </NFormItem>
          <NFormItem label="状态">
            <NSelect
              v-model:value="query.attack"
              :options="[
                { label: '仅攻击', value: '1' },
                { label: '非攻击', value: '0' }
              ]"
              clearable
              placeholder="全部"
              class="w-28"
            />
          </NFormItem>
          <NFormItem>
            <NButton type="primary" @click="query.page = 1; load()">查询</NButton>
          </NFormItem>
        </NForm>
      </NCard>
    </div>

    <!-- 流量列表 -->
    <NCard :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="items" :loading="loading" :bordered="false" size="small" />
      <div class="mt-4 flex justify-end">
        <NPagination v-model:page="query.page" :page-size="query.page_size" :item-count="total" @update:page="load" />
      </div>
    </NCard>
  </div>
</template>
