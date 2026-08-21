<script setup lang="ts">
import { h, onMounted, ref } from 'vue';
import { NButton, NCard, NDataTable, NInput, NModal, NPopconfirm, NSelect, NTag } from 'naive-ui';
import { clearErrorLogs, consumeErrorLogs, fetchErrorLogs, fetchErrorStats } from '@/service/api';

const rows = ref<Api.Waf.ErrorLogRow[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = 20;
const loading = ref(false);
const consuming = ref(false);

const stats = ref<Api.Waf.ErrorStats | null>(null);

const filterLevel = ref<string | null>(null);
const filterSource = ref('');
const filterKeyword = ref('');

const detail = ref<Api.Waf.ErrorLogRow | null>(null);

const levelOptions = [
  { label: '全部级别', value: '' },
  { label: '错误', value: 'error' },
  { label: '警告', value: 'warn' }
];

function fmtTime(t: string | null | undefined) {
  if (!t) return '-';
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '');
}

async function load() {
  loading.value = true;
  try {
    const params: Record<string, string | number> = { page: page.value, page_size: pageSize };
    if (filterLevel.value) params.level = filterLevel.value;
    if (filterSource.value.trim()) params.source = filterSource.value.trim();
    if (filterKeyword.value.trim()) params.keyword = filterKeyword.value.trim();
    const res = await fetchErrorLogs(params);
    rows.value = res.data?.items ?? [];
    total.value = res.data?.total ?? 0;
  } finally {
    loading.value = false;
  }
}

async function loadStats() {
  const res = await fetchErrorStats();
  stats.value = res.data ?? null;
}

async function refresh() {
  await Promise.all([load(), loadStats()]);
}

function search() {
  page.value = 1;
  load();
}

async function doConsume() {
  consuming.value = true;
  try {
    const res = await consumeErrorLogs();
    if (res.error) {
      window.$message?.error('消费失败');
      return;
    }
    window.$message?.success(`已消费 ${res.data?.consumed ?? 0} 条`);
    await refresh();
  } finally {
    consuming.value = false;
  }
}

async function doClear() {
  const res = await clearErrorLogs();
  if (res.error) {
    window.$message?.error('清空失败');
    return;
  }
  window.$message?.success('已清空');
  await refresh();
}

const columns = [
  { title: '时间', key: 'time', width: 165, render: (row: Api.Waf.ErrorLogRow) => h('span', { class: 'text-xs' }, fmtTime(row.time)) },
  {
    title: '级别',
    key: 'level',
    width: 80,
    render: (row: Api.Waf.ErrorLogRow) =>
      row.level === 'error'
        ? h(NTag, { size: 'small', type: 'error', bordered: false }, { default: () => '错误' })
        : h(NTag, { size: 'small', type: 'warning', bordered: false }, { default: () => '警告' })
  },
  {
    title: '来源',
    key: 'source',
    width: 110,
    render: (row: Api.Waf.ErrorLogRow) => h(NTag, { size: 'small', bordered: false }, { default: () => row.source || '-' })
  },
  {
    title: '消息',
    key: 'message',
    ellipsis: { tooltip: true },
    render: (row: Api.Waf.ErrorLogRow) => h('span', { class: 'font-mono text-xs' }, row.message)
  },
  {
    title: '客户端 IP',
    key: 'client_ip',
    width: 130,
    render: (row: Api.Waf.ErrorLogRow) => h('span', { class: 'font-mono text-xs' }, row.client_ip || '-')
  },
  {
    title: '主机',
    key: 'host',
    width: 150,
    ellipsis: { tooltip: true },
    render: (row: Api.Waf.ErrorLogRow) => h('span', { class: 'text-xs' }, row.host || '-')
  },
  {
    title: '操作',
    key: 'actions',
    width: 70,
    render: (row: Api.Waf.ErrorLogRow) =>
      h(NButton, { size: 'tiny', secondary: true, onClick: () => (detail.value = row) }, { default: () => '详情' })
  }
];

onMounted(refresh);
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">报错汇总</h2>
        <p class="text-sm text-[rgb(125,125,125)]">
          引擎各环节 ERR/WARN 级错误自动上报汇总，无需逐台翻查 nginx error.log；引擎侧自带限速与同签名去重
        </p>
      </div>
      <div class="flex gap-2">
        <NPopconfirm @positive-click="doClear">
          <template #trigger>
            <NButton type="error" secondary>清空记录</NButton>
          </template>
          确认清空全部报错记录？
        </NPopconfirm>
        <NButton :loading="consuming" @click="doConsume">立即拉取</NButton>
        <NButton type="primary" :loading="loading" @click="refresh">刷新</NButton>
      </div>
    </div>

    <NCard size="small" :bordered="true" class="shadow-sm">
      <div class="flex flex-wrap items-center gap-3">
        <div class="flex items-center gap-2">
          <NTag :type="stats && stats.error > 0 ? 'error' : 'default'" size="large" round>
            近24h 错误：{{ stats?.error ?? 0 }}
          </NTag>
          <NTag :type="stats && stats.warn > 0 ? 'warning' : 'default'" size="large" round>
            近24h 警告：{{ stats?.warn ?? 0 }}
          </NTag>
        </div>
        <div class="ml-auto flex flex-wrap items-center gap-2">
          <NSelect v-model:value="filterLevel" :options="levelOptions" class="w-32" size="small" @update:value="search" />
          <NInput v-model:value="filterSource" placeholder="来源模块（如 access）" size="small" class="w-44" clearable @keyup.enter="search" />
          <NInput v-model:value="filterKeyword" placeholder="关键字：消息 / IP / 主机 / req_id" size="small" class="w-60" clearable @keyup.enter="search" />
          <NButton size="small" type="primary" secondary @click="search">查询</NButton>
        </div>
      </div>
    </NCard>

    <NCard size="small" :bordered="true" class="shadow-sm">
      <NDataTable
        :columns="columns"
        :data="rows"
        :loading="loading"
        :pagination="{
          page,
          pageSize,
          itemCount: total,
          onChange: (p: number) => { page = p; load(); }
        }"
        :bordered="false"
        size="small"
        remote
      />
    </NCard>

    <NModal :show="detail !== null" preset="card" title="报错详情" class="w-[640px]" @update:show="(v: boolean) => { if (!v) detail = null; }">
      <template v-if="detail">
        <div class="space-y-2 text-sm">
          <div class="flex gap-2">
            <span class="w-20 shrink-0 text-[rgb(125,125,125)]">时间</span>
            <span>{{ fmtTime(detail.time) }}</span>
          </div>
          <div class="flex gap-2">
            <span class="w-20 shrink-0 text-[rgb(125,125,125)]">级别</span>
            <NTag :size="'small'" :type="detail.level === 'error' ? 'error' : 'warning'" :bordered="false">
              {{ detail.level === 'error' ? '错误' : '警告' }}
            </NTag>
          </div>
          <div class="flex gap-2">
            <span class="w-20 shrink-0 text-[rgb(125,125,125)]">来源</span>
            <span>{{ detail.source }}</span>
          </div>
          <div class="flex gap-2">
            <span class="w-20 shrink-0 text-[rgb(125,125,125)]">消息</span>
            <span class="font-mono break-all whitespace-pre-wrap">{{ detail.message }}</span>
          </div>
          <div class="flex gap-2">
            <span class="w-20 shrink-0 text-[rgb(125,125,125)]">req_id</span>
            <span class="font-mono">{{ detail.req_id || '-' }}</span>
          </div>
          <div class="flex gap-2">
            <span class="w-20 shrink-0 text-[rgb(125,125,125)]">客户端 IP</span>
            <span class="font-mono">{{ detail.client_ip || '-' }}</span>
          </div>
          <div class="flex gap-2">
            <span class="w-20 shrink-0 text-[rgb(125,125,125)]">主机</span>
            <span>{{ detail.host || '-' }}</span>
          </div>
          <div class="flex gap-2">
            <span class="w-20 shrink-0 text-[rgb(125,125,125)]">URI</span>
            <span class="font-mono break-all">{{ detail.uri || '-' }}</span>
          </div>
          <div class="flex gap-2">
            <span class="w-20 shrink-0 text-[rgb(125,125,125)]">引擎版本</span>
            <span>{{ detail.engine_version || '-' }}</span>
          </div>
        </div>
      </template>
    </NModal>
  </div>
</template>
