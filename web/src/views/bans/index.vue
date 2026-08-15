<script setup lang="ts">
import { h, onMounted, ref } from 'vue';
import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NModal,
  NPopconfirm,
  NRadio,
  NRadioGroup,
  NTag
} from 'naive-ui';
import { createBan, fetchBans, unbanIP } from '@/service/api';

const bans = ref<Api.Waf.BanEntry[]>([]);
const loading = ref(false);
const showModal = ref(false);
const form = ref<{ ip: string; ua: string; hours: number; dimension: 'ip' | 'ip_ua' }>({
  ip: '',
  ua: '',
  hours: 24,
  dimension: 'ip'
});

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

async function doCreate() {
  const f = form.value;
  if (!f.ip) {
    window.$message?.error('请输入 IP');
    return;
  }
  await createBan({
    ip: f.ip,
    ua: f.dimension === 'ip_ua' ? f.ua : '',
    hours: f.hours
  });
  window.$message?.success(
    f.dimension === 'ip_ua' ? `已按 IP+UA 维度封禁 ${f.ip}，引擎 5 秒内生效` : `已封禁 ${f.ip}，引擎 5 秒内生效`
  );
  showModal.value = false;
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
    title: '维度',
    key: 'ua',
    width: 200,
    render: (row: Api.Waf.BanEntry) =>
      row.ua
        ? h('div', { class: 'space-y-0.5' }, [
            h(NTag, { size: 'small', type: 'warning', bordered: false }, { default: () => 'IP+UA' }),
            h('div', { class: 'max-w-[140px] truncate text-[11px] text-[rgb(125,125,125)]', title: row.ua }, row.ua)
          ])
        : h(NTag, { size: 'small', type: 'default', bordered: false }, { default: () => '仅 IP' })
  },
  {
    title: '类型',
    key: 'permanent',
    width: 80,
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
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">封禁管理</h2>
        <p class="text-sm text-[rgb(125,125,125)]">
          支持按 IP 或 IP+UA 维度封禁；解除或过期后引擎 5 秒内热更新生效
        </p>
      </div>
      <NButton type="primary" @click="showModal = true">新增封禁</NButton>
    </div>

    <NCard :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="bans" :loading="loading" :bordered="false" size="small" />
    </NCard>

    <NModal v-model:show="showModal" preset="card" title="新增封禁" style="width: 480px">
      <NForm label-placement="left" label-width="90">
        <NFormItem label="封禁维度">
          <NRadioGroup v-model:value="form.dimension">
            <NRadio value="ip">仅 IP</NRadio>
            <NRadio value="ip_ua">IP + UA</NRadio>
          </NRadioGroup>
        </NFormItem>
        <NFormItem label="IP / CIDR">
          <NInput v-model:value="form.ip" placeholder="如 1.2.3.4 或 10.0.0.0/8" />
        </NFormItem>
        <NFormItem v-if="form.dimension === 'ip_ua'" label="User-Agent">
          <NInput v-model:value="form.ua" placeholder="UA 子串匹配，如 python-requests（不能含 |）" />
        </NFormItem>
        <NFormItem label="时长(小时)">
          <NInputNumber v-model:value="form.hours" :min="0" style="width: 100%">
            <template #suffix>
              <span class="text-xs text-[rgb(125,125,125)]">0 = 永久</span>
            </template>
          </NInputNumber>
        </NFormItem>
      </NForm>
      <template #footer>
        <div class="flex justify-end gap-2">
          <NButton @click="showModal = false">取消</NButton>
          <NButton type="primary" @click="doCreate">封禁</NButton>
        </div>
      </template>
    </NModal>
  </div>
</template>
