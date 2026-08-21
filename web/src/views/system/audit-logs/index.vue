<script setup lang="ts">
import { h, onMounted, ref } from 'vue';
import { NButton, NCard, NDataTable, NInput, NSelect, NTag } from 'naive-ui';
import { fetchAuditLogs } from '@/service/api';

const items = ref<Api.Waf.AuditLog[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const loading = ref(false);
const filterUsername = ref('');
const filterAction = ref('');

const actionMeta: Record<string, { label: string; type: 'success' | 'warning' | 'error' | 'default' | 'info' }> = {
  login: { label: '登录', type: 'info' },
  create: { label: '新建', type: 'success' },
  update: { label: '修改', type: 'warning' },
  delete: { label: '删除', type: 'error' },
  publish: { label: '发布', type: 'warning' },
  rollback: { label: '回滚', type: 'error' },
  ban: { label: '封禁', type: 'error' },
  other: { label: '其他', type: 'default' }
};

function fmtTime(t: string) {
  if (!t) return '-';
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '');
}

async function load() {
  loading.value = true;
  try {
    const res = await fetchAuditLogs({
      page: page.value,
      page_size: pageSize.value,
      username: filterUsername.value,
      action: filterAction.value
    });
    items.value = res.data?.items ?? [];
    total.value = res.data?.total ?? 0;
  } finally {
    loading.value = false;
  }
}

onMounted(load);

const columns = [
  {
    title: '时间',
    key: 'created_at',
    width: 160,
    render: (row: Api.Waf.AuditLog) => fmtTime(row.created_at)
  },
  { title: '操作人', key: 'username', width: 110 },
  {
    title: '动作',
    key: 'action',
    width: 90,
    render: (row: Api.Waf.AuditLog) => {
      const meta = actionMeta[row.action] || actionMeta.other;
      return h(NTag, { type: meta.type, size: 'small', bordered: false }, { default: () => meta.label });
    }
  },
  { title: '方法', key: 'method', width: 80 },
  { title: '路径', key: 'path' },
  { title: '详情', key: 'detail', ellipsis: { tooltip: true } },
  { title: '来源 IP', key: 'client_ip', width: 130 },
  {
    title: '结果',
    key: 'success',
    width: 80,
    render: (row: Api.Waf.AuditLog) =>
      row.success
        ? h(NTag, { type: 'success', size: 'small', bordered: false }, { default: () => '成功' })
        : h(NTag, { type: 'error', size: 'small', bordered: false }, { default: () => '失败' })
  }
];
</script>

<template>
  <NCard :bordered="false" class="card-wrapper" title="操作审计日志">
    <template #header-extra>
      <span class="text-xs text-[rgb(125,125,125)]">记录后台写操作与登录事件，日志不可删除</span>
    </template>
    <div class="mb-3 flex gap-3">
      <NInput v-model:value="filterUsername" placeholder="按操作人过滤" clearable style="width: 180px" @keyup.enter="page = 1; load()" />
      <NSelect
        v-model:value="filterAction"
        placeholder="按动作过滤"
        clearable
        style="width: 140px"
        :options="Object.entries(actionMeta).map(([k, v]) => ({ label: v.label, value: k }))"
        @update:value="page = 1; load()"
      />
      <NButton type="primary" size="small" @click="page = 1; load()">查询</NButton>
    </div>
    <NDataTable
      :columns="columns"
      :data="items"
      :loading="loading"
      :pagination="{
        page: page,
        pageSize,
        itemCount: total,
        onChange: p => { page = p; load(); }
      }"
      size="small"
      :bordered="false"
    />
  </NCard>
</template>
