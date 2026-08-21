<script setup lang="ts">
import { h, onMounted, ref } from 'vue';
import { NButton, NCard, NDataTable, NPopconfirm, NTag } from 'naive-ui';
import { consumeRulePerf, fetchRulePerf, resetRulePerf } from '@/service/api';

const rows = ref<Api.Waf.RulePerfRow[]>([]);
const loading = ref(false);
const resetting = ref(false);

function fmtTime(t: string | null) {
  if (!t) return '-';
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '');
}

function fmtNum(n: number) {
  return (n ?? 0).toLocaleString('en-US');
}

function fmtUs(us: number) {
  const v = us ?? 0;
  if (v < 1000) return `${Math.round(v)} µs`;
  return `${(v / 1000).toFixed(2)} ms`;
}

async function load() {
  loading.value = true;
  try {
    const res = await fetchRulePerf();
    rows.value = res.data?.items ?? [];
  } finally {
    loading.value = false;
  }
}

async function doRefresh() {
  loading.value = true;
  try {
    await consumeRulePerf();
    const res = await fetchRulePerf();
    rows.value = res.data?.items ?? [];
  } finally {
    loading.value = false;
  }
}

async function doReset() {
  resetting.value = true;
  try {
    const res = await resetRulePerf();
    if (res.error) {
      window.$message?.error('重置失败');
      return;
    }
    window.$message?.success('已清空规则性能统计');
    await load();
  } finally {
    resetting.value = false;
  }
}

const columns = [
  { title: '规则ID', key: 'rule_id', width: 100, render: (row: Api.Waf.RulePerfRow) => h('span', { class: 'font-mono' }, row.rule_id) },
  {
    title: '名称',
    key: 'name',
    ellipsis: { tooltip: true },
    render: (row: Api.Waf.RulePerfRow) =>
      row.name
        ? h('span', {}, row.name)
        : h('span', { class: 'text-[rgb(170,170,170)]' }, '已删除')
  },
  {
    title: '分组',
    key: 'group',
    width: 120,
    render: (row: Api.Waf.RulePerfRow) =>
      row.group
        ? h(NTag, { size: 'small', bordered: false }, { default: () => row.group })
        : h('span', { class: 'text-[rgb(170,170,170)]' }, '-')
  },
  {
    title: '状态',
    key: 'enabled',
    width: 90,
    render: (row: Api.Waf.RulePerfRow) => {
      if (!row.name) return h(NTag, { size: 'small', type: 'default', bordered: false }, { default: () => '已删除' });
      return row.enabled
        ? h(NTag, { size: 'small', type: 'success', bordered: false }, { default: () => '正常' })
        : h(NTag, { size: 'small', type: 'warning', bordered: false }, { default: () => '已禁用' });
    }
  },
  {
    title: '评估次数',
    key: 'hits',
    width: 110,
    align: 'right' as const,
    render: (row: Api.Waf.RulePerfRow) => h('span', { class: 'font-mono' }, fmtNum(row.hits))
  },
  {
    title: '平均耗时',
    key: 'avg_us',
    width: 110,
    align: 'right' as const,
    render: (row: Api.Waf.RulePerfRow) => h('span', { class: 'font-mono' }, fmtUs(row.avg_us))
  },
  {
    title: '最大耗时',
    key: 'max_us',
    width: 110,
    align: 'right' as const,
    render: (row: Api.Waf.RulePerfRow) => h('span', { class: 'font-mono' }, fmtUs(row.max_us))
  },
  {
    title: '累计耗时',
    key: 'total_us',
    width: 120,
    align: 'right' as const,
    render: (row: Api.Waf.RulePerfRow) => h('span', { class: 'font-mono' }, fmtUs(row.total_us))
  },
  {
    title: '更新时间',
    key: 'updated_at',
    width: 170,
    render: (row: Api.Waf.RulePerfRow) => h('span', { class: 'text-xs' }, fmtTime(row.updated_at))
  }
];

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">规则性能画像</h2>
        <p class="text-sm text-[rgb(125,125,125)]">数据由 WAF 引擎每分钟上报各规则评估耗时，用于定位高开销规则</p>
      </div>
      <div class="flex gap-2">
        <NPopconfirm :disabled="resetting" @positive-click="doReset">
          <template #trigger>
            <NButton type="error" secondary :loading="resetting">重置统计</NButton>
          </template>
          确认清空全部规则性能统计？该操作不可恢复。
        </NPopconfirm>
        <NButton type="primary" :loading="loading" @click="doRefresh">刷新</NButton>
      </div>
    </div>

    <NCard :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="rows" :loading="loading" :bordered="false" size="small">
        <template #empty>
          <NEmpty description="暂无数据，引擎上报后约 1 分钟可见" />
        </template>
      </NDataTable>
    </NCard>
  </div>
</template>
