<script setup lang="ts">
import { h, onMounted, ref } from 'vue';
import { NButton, NCard, NDataTable, NPopconfirm, NTag } from 'naive-ui';
import { fetchBans, unbanIP } from '@/service/api';

const bans = ref<Api.Waf.BanEntry[]>([]);
const loading = ref(false);

async function load() {
  loading.value = true;
  try {
    const res = await fetchBans();
    bans.value = res.data ?? [];
  } finally {
    loading.value = false;
  }
}

async function doUnban(row: Api.Waf.BanEntry) {
  await unbanIP(row.ip);
  window.$message?.success(`已解除 ${row.ip} 的封禁，引擎 5 秒内生效`);
  await load();
}

function formatExpire(ts: number | null) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

const columns = [
  { title: 'IP', key: 'ip', render: (row: Api.Waf.BanEntry) => h('span', { class: 'font-mono text-sm' }, row.ip) },
  {
    title: '类型',
    key: 'permanent',
    width: 90,
    render: (row: Api.Waf.BanEntry) =>
      h(NTag, { size: 'small', type: row.permanent ? 'error' : 'warning', bordered: false }, { default: () => (row.permanent ? '永久' : '临时') })
  },
  { title: '解封时间', key: 'expires_at', render: (row: Api.Waf.BanEntry) => h('span', { class: 'text-xs' }, row.permanent ? '—' : formatExpire(row.expires_at)) },
  {
    title: '操作',
    key: 'action',
    width: 90,
    render: (row: Api.Waf.BanEntry) =>
      h(
        NPopconfirm,
        { onPositiveClick: () => doUnban(row) },
        {
          trigger: () => h(NButton, { size: 'small', quaternary: true, type: 'primary' }, { default: () => '解除封禁' }),
          default: () => `确认解除 ${row.ip} 的封禁？`
        }
      )
  }
];

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <div>
      <h2 class="text-xl font-semibold">封禁管理</h2>
      <p class="text-sm text-[rgb(125,125,125)]">
        临时/永久封禁 IP 列表（攻击事件页「封禁」操作写入）；解除或过期后引擎 5 秒内热更新生效
      </p>
    </div>

    <NCard :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="bans" :loading="loading" :bordered="false" size="small" />
    </NCard>
  </div>
</template>
