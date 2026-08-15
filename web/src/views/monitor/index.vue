<script setup lang="ts">
import { h, onMounted, onUnmounted, ref } from 'vue';
import { NCard, NDataTable, NGrid, NGi, NStatistic, NTag } from 'naive-ui';
import { useEcharts } from '@/hooks/common/echarts';
import type { ECOption } from '@/hooks/common/echarts';
import { fetchEngines, fetchRealtime } from '@/service/api';

const engines = ref<Api.Waf.EngineStatus[]>([]);
const points = ref<{ ts: number; total: number; attack: number }[]>([]);
const qps = ref(0);
const atkQps = ref(0);
let timer: ReturnType<typeof setInterval> | null = null;

function fmtTime(ts: number) {
  const d = new Date(ts * 1000);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// 实时 QPS 曲线（最近 10 分钟）
const trendOption = (): ECOption => ({
  tooltip: { trigger: 'axis' },
  legend: { data: ['请求 QPS', '攻击 QPS'], top: 0 },
  grid: { left: 48, right: 16, top: 32, bottom: 8 },
  xAxis: { type: 'category', data: points.value.map(p => fmtTime(p.ts)) },
  yAxis: { type: 'value', minInterval: 1 },
  series: [
    {
      name: '请求 QPS',
      type: 'line',
      smooth: true,
      showSymbol: false,
      itemStyle: { color: '#2563eb' },
      areaStyle: { color: 'rgba(37,99,235,0.12)' },
      data: points.value.map(p => p.total)
    },
    {
      name: '攻击 QPS',
      type: 'line',
      smooth: true,
      showSymbol: false,
      itemStyle: { color: '#ef4444' },
      areaStyle: { color: 'rgba(239,68,68,0.1)' },
      data: points.value.map(p => p.attack)
    }
  ]
});
const { domRef: trendRef, updateOptions: updateTrend } = useEcharts(trendOption);

async function load() {
  try {
    const [en, rt] = await Promise.all([
      fetchEngines().catch(() => ({ data: { engines: [] as Api.Waf.EngineStatus[] } })),
      fetchRealtime(10).catch(() => ({ data: { points: [] as { ts: number; total: number; attack: number }[] } }))
    ]);
    engines.value = en.data?.engines ?? [];
    points.value = rt.data?.points ?? [];
    const now = Math.floor(Date.now() / 1000);
    const total = points.value.filter(p => now - p.ts <= 60).reduce((a, p) => a + p.total, 0);
    const atk = points.value.filter(p => now - p.ts <= 60).reduce((a, p) => a + p.attack, 0);
    qps.value = Number((total / 60).toFixed(2));
    atkQps.value = Number((atk / 60).toFixed(2));
    updateTrend(() => trendOption());
  } catch {
    /* 网络错误由请求层提示 */
  }
}

onMounted(() => {
  load();
  timer = setInterval(load, 5000);
});
onUnmounted(() => {
  if (timer) clearInterval(timer);
});

const engineColumns = [
  { title: 'Worker PID', key: 'pid', width: 110 },
  {
    title: '状态',
    key: 'online',
    width: 90,
    render: (row: Api.Waf.EngineStatus) =>
      row.online
        ? h(NTag, { type: 'success', size: 'small', bordered: false }, { default: () => '在线' })
        : h(NTag, { type: 'error', size: 'small', bordered: false }, { default: () => '离线' })
  },
  {
    title: '规则同步',
    key: 'rule_synced',
    width: 100,
    render: (row: Api.Waf.EngineStatus) =>
      row.rule_synced
        ? h(NTag, { type: 'success', size: 'small', bordered: false }, { default: () => '已同步' })
        : h(NTag, { type: 'warning', size: 'small', bordered: false }, { default: () => '待加载' })
  },
  { title: '引擎版本', key: 'engine_version' },
  { title: '规则版本', key: 'ruleset_version' },
  { title: '配置版本', key: 'config_version' },
  { title: '触发规则版本', key: 'trigger_version' },
  {
    title: '最后心跳',
    key: 'last_seen',
    render: (row: Api.Waf.EngineStatus) => fmtTime(row.last_seen)
  }
];
</script>

<template>
  <div class="space-y-4">
    <NGrid :x-gap="16" :y-gap="16" cols="s:1 m:3">
      <NGi>
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="实时 QPS" :value="qps">
            <template #suffix><span class="text-sm">req/s</span></template>
          </NStatistic>
        </NCard>
      </NGi>
      <NGi>
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="实时攻击 QPS" :value="atkQps">
            <template #suffix><span class="text-sm">req/s</span></template>
          </NStatistic>
        </NCard>
      </NGi>
      <NGi>
        <NCard :bordered="false" class="card-wrapper">
          <NStatistic label="引擎 Worker" :value="engines.length">
            <template #suffix><span class="text-sm">个</span></template>
          </NStatistic>
        </NCard>
      </NGi>
    </NGrid>

    <NCard :bordered="false" class="card-wrapper" title="实时流量曲线（近 10 分钟，5 秒刷新）">
      <div ref="trendRef" class="h-72 w-full" />
    </NCard>

    <NCard :bordered="false" class="card-wrapper" title="引擎健康状态">
      <template #header-extra>
        <span class="text-xs text-[rgb(125,125,125)]">心跳 10 秒一次，30 秒无心跳视为离线</span>
      </template>
      <NDataTable :columns="engineColumns" :data="engines" size="small" :bordered="false" />
    </NCard>
  </div>
</template>
