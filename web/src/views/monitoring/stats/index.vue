<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue';
import { NButton, NCard, NGrid, NGi, NSelect, NTag } from 'naive-ui';
import { useEcharts } from '@/hooks/common/echarts';
import type { ECOption } from '@/hooks/common/echarts';
import { fetchTrafficStatReport } from '@/service/api';

const report = ref<Api.Waf.TrafficStatReport | null>(null);
const loading = ref(false);
const hours = ref(24);

const hoursOptions = [
  { label: '近 24 小时', value: 24 },
  { label: '近 48 小时', value: 48 },
  { label: '近 7 天', value: 168 },
  { label: '近 30 天', value: 720 }
];

const summaryCards = computed(() => {
  const s = report.value?.summary;
  return [
    { label: '总请求', value: (s?.total ?? 0).toLocaleString(), color: '#2563eb' },
    {
      label: '拦截请求',
      value: `${(s?.blocked ?? 0).toLocaleString()}（${(s?.block_rate ?? 0).toFixed(1)}%）`,
      color: '#ef4444'
    },
    { label: '攻击请求', value: (s?.attacks ?? 0).toLocaleString(), color: '#f59e0b' },
    { label: '独立 IP', value: (s?.unique_ips ?? 0).toLocaleString(), color: '#10b981' },
    { label: '平均耗时', value: `${(s?.avg_response_ms ?? 0).toFixed(1)} ms`, color: '#8b5cf6' }
  ];
});

// —— 请求趋势（总量/拦截/攻击） ——
const trendOption = (): ECOption => {
  const series = report.value?.series ?? [];
  const hasDays = (report.value?.hours ?? 24) > 48;
  return {
    tooltip: { trigger: 'axis' },
    legend: { data: ['总请求', '拦截', '攻击'], top: 0 },
    grid: { left: 48, right: 16, top: 36, bottom: 28 },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: series.map(p => (hasDays ? p.label : p.label)),
      axisLabel: { rotate: hasDays ? 0 : 45 }
    },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      {
        name: '总请求',
        type: 'line',
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#2563eb' },
        areaStyle: { color: 'rgba(37,99,235,0.12)' },
        data: series.map(p => p.total)
      },
      {
        name: '拦截',
        type: 'line',
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#ef4444' },
        areaStyle: { color: 'rgba(239,68,68,0.08)' },
        data: series.map(p => p.blocked)
      },
      {
        name: '攻击',
        type: 'line',
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#f59e0b' },
        data: series.map(p => p.attacks)
      }
    ]
  };
};
const { domRef: trendRef, updateOptions: updateTrend } = useEcharts(trendOption);

// —— 状态码分布（环形图） ——
const statusColors = ['2563eb', '10b981', 'ef4444', 'f59e0b', '8b5cf6', '06b6d4', '64748b', 'ec4899'];
const statusOption = (): ECOption => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
  legend: { orient: 'vertical', right: 0, top: 'center', type: 'scroll' },
  series: [
    {
      name: '状态分布',
      type: 'pie',
      radius: ['52%', '78%'],
      center: ['38%', '50%'],
      avoidLabelOverlap: true,
      itemStyle: { borderRadius: 6, borderColor: '#fff', borderWidth: 2 },
      label: { show: false },
      emphasis: { label: { show: true, fontSize: 14, fontWeight: 'bold' } },
      data: (report.value?.status_dist ?? []).map((s, i) => ({
        name: s.name,
        value: s.count,
        itemStyle: { color: `#${statusColors[i % statusColors.length]}` }
      }))
    }
  ]
});
const { domRef: statusRef, updateOptions: updateStatus } = useEcharts(statusOption);

// —— TopN 横向条形图通用 option 工厂 ——
function barOption(data: Api.Waf.NameCount[], color: string): ECOption {
  const items = [...data].reverse();
  return {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: (params: unknown) => {
        const arr = params as { name: string; dataIndex: number }[];
        const idx = arr[0]?.dataIndex ?? 0;
        const item = items[idx];
        if (!item) return '';
        return `${item.name}<br/>请求 ${item.count.toLocaleString()} · 拦截 ${item.blocked.toLocaleString()}`;
      }
    },
    grid: { left: 8, right: 24, top: 8, bottom: 24, containLabel: true },
    xAxis: { type: 'value', minInterval: 1 },
    yAxis: {
      type: 'category',
      data: items.map(i => (i.name.length > 28 ? `${i.name.slice(0, 28)}…` : i.name)),
      axisLabel: { fontSize: 11 }
    },
    series: [
      {
        type: 'bar',
        data: items.map(i => i.count),
        itemStyle: { color, borderRadius: [0, 4, 4, 0] },
        barWidth: 12
      }
    ]
  };
}
const ipOption = () => barOption(report.value?.top_ips ?? [], '#2563eb');
const uriOption = () => barOption(report.value?.top_uris ?? [], '#8b5cf6');
const hostOption = () => barOption(report.value?.top_hosts ?? [], '#10b981');
const { domRef: ipRef, updateOptions: updateIp } = useEcharts(ipOption);
const { domRef: uriRef, updateOptions: updateUri } = useEcharts(uriOption);
const { domRef: hostRef, updateOptions: updateHost } = useEcharts(hostOption);

async function load() {
  loading.value = true;
  try {
    const res = await fetchTrafficStatReport(hours.value);
    report.value = res.data ?? null;
    // 数据更新后必须传最新 option 工厂，否则图表停留在初始空数据
    await Promise.all([
      updateTrend(() => trendOption()),
      updateStatus(() => statusOption()),
      updateIp(() => ipOption()),
      updateUri(() => uriOption()),
      updateHost(() => hostOption())
    ]);
  } finally {
    loading.value = false;
  }
}

function changeHours(v: number) {
  hours.value = v;
  load();
}

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">流量统计</h2>
        <p class="text-sm text-[rgb(125,125,125)]">基于全量流量记录的多维度统计分析（需开启全量记录模式）</p>
      </div>
      <div class="flex gap-2">
        <NSelect :value="hours" :options="hoursOptions" class="w-32" @update:value="changeHours" />
        <NButton type="primary" :loading="loading" @click="load">刷新</NButton>
      </div>
    </div>

    <!-- 汇总指标卡 -->
    <NGrid responsive="screen" item-responsive :x-gap="12" :y-gap="12" cols="2 s:3 l:5">
      <NGi v-for="card in summaryCards" :key="card.label" span="1">
        <NCard size="small" :bordered="true" class="shadow-sm">
          <div class="flex flex-col gap-1">
            <span class="text-xs text-[rgb(125,125,125)]">{{ card.label }}</span>
            <span class="text-xl font-semibold" :style="{ color: card.color }">{{ card.value }}</span>
          </div>
        </NCard>
      </NGi>
    </NGrid>

    <!-- 趋势图 -->
    <NCard title="请求趋势" size="small" :bordered="true" class="shadow-sm">
      <div ref="trendRef" class="h-80" />
    </NCard>

    <!-- 状态分布 + TopN -->
    <NGrid responsive="screen" item-responsive :x-gap="16" :y-gap="16" cols="1 l:2">
      <NGi span="1">
        <NCard size="small" :bordered="true" class="shadow-sm h-full">
          <template #header>
            <span class="text-sm font-medium">状态码分布</span>
          </template>
          <div ref="statusRef" class="h-72" />
          <div v-if="(report?.status_dist?.length ?? 0) === 0" class="flex justify-center py-16">
            <NTag :bordered="false">暂无数据</NTag>
          </div>
        </NCard>
      </NGi>
      <NGi span="1">
        <NCard size="small" :bordered="true" class="shadow-sm h-full">
          <template #header>
            <span class="text-sm font-medium">Top IP</span>
          </template>
          <div ref="ipRef" class="h-72" />
        </NCard>
      </NGi>
      <NGi span="1">
        <NCard size="small" :bordered="true" class="shadow-sm h-full">
          <template #header>
            <span class="text-sm font-medium">Top URI</span>
          </template>
          <div ref="uriRef" class="h-72" />
        </NCard>
      </NGi>
      <NGi span="1">
        <NCard size="small" :bordered="true" class="shadow-sm h-full">
          <template #header>
            <span class="text-sm font-medium">Top 主机</span>
          </template>
          <div ref="hostRef" class="h-72" />
        </NCard>
      </NGi>
    </NGrid>
  </div>
</template>
