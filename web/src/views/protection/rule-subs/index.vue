<script setup lang="ts">
import { h, onMounted, reactive, ref } from 'vue';
import { NButton, NCard, NDataTable, NInput, NInputNumber, NPopconfirm, NSwitch, NTag } from 'naive-ui';
import {
  createRuleSub,
  deleteRuleSub,
  fetchRuleSubs,
  setRuleSubEnabled,
  syncRuleSub,
  updateRuleSub
} from '@/service/api';

const rows = ref<Api.Waf.RuleSubscription[]>([]);
const loading = ref(false);
const syncingId = ref<number | null>(null);

const showModal = ref(false);
const saving = ref(false);
const editing = ref<Api.Waf.RuleSubscription | null>(null);
const form = reactive({
  name: '',
  url: '',
  interval_min: 1440,
  auto_publish: false
});

function fmtTime(t: string | null | undefined) {
  if (!t) return '-';
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '');
}

async function load() {
  loading.value = true;
  try {
    const res = await fetchRuleSubs();
    rows.value = res.data ?? [];
  } finally {
    loading.value = false;
  }
}

function openCreate() {
  editing.value = null;
  form.name = '';
  form.url = '';
  form.interval_min = 1440;
  form.auto_publish = false;
  showModal.value = true;
}

function openEdit(row: Api.Waf.RuleSubscription) {
  editing.value = row;
  form.name = row.name;
  form.url = row.url;
  form.interval_min = row.interval_min || 1440;
  form.auto_publish = !!row.auto_publish;
  showModal.value = true;
}

async function doSave() {
  if (!form.name.trim()) {
    window.$message?.error('请输入订阅名称');
    return;
  }
  if (!/^https?:\/\//.test(form.url.trim())) {
    window.$message?.error('URL 必须以 http:// 或 https:// 开头');
    return;
  }
  saving.value = true;
  try {
    const payload = {
      name: form.name.trim(),
      url: form.url.trim(),
      interval_min: form.interval_min > 0 ? form.interval_min : 1440,
      auto_publish: form.auto_publish
    };
    const res = editing.value
      ? await updateRuleSub(editing.value.id, payload)
      : await createRuleSub(payload);
    if (res.error) {
      window.$message?.error('保存失败');
      return;
    }
    window.$message?.success(editing.value ? '已更新' : '已创建');
    showModal.value = false;
    await load();
  } finally {
    saving.value = false;
  }
}

async function doSync(row: Api.Waf.RuleSubscription) {
  syncingId.value = row.id;
  try {
    const res = await syncRuleSub(row.id);
    if (res.error) {
      window.$message?.error('同步失败');
      return;
    }
    window.$message?.success(`同步完成，入库 ${res.data?.imported ?? 0} 条规则`);
    await load();
  } finally {
    syncingId.value = null;
  }
}

async function doToggle(row: Api.Waf.RuleSubscription, enabled: boolean) {
  const res = await setRuleSubEnabled(row.id, enabled);
  if (res.error) {
    window.$message?.error('操作失败');
    return;
  }
  row.enabled = enabled;
}

async function doDelete(row: Api.Waf.RuleSubscription) {
  const res = await deleteRuleSub(row.id);
  if (res.error) {
    window.$message?.error('删除失败');
    return;
  }
  window.$message?.success('已删除并清理该订阅的规则');
  await load();
}

const columns = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '名称', key: 'name', width: 160, ellipsis: { tooltip: true } },
  {
    title: '订阅地址',
    key: 'url',
    ellipsis: { tooltip: true },
    render: (row: Api.Waf.RuleSubscription) => h('span', { class: 'font-mono text-xs' }, row.url)
  },
  {
    title: '周期',
    key: 'interval_min',
    width: 90,
    render: (row: Api.Waf.RuleSubscription) => `${row.interval_min} 分钟`
  },
  {
    title: '自动发布',
    key: 'auto_publish',
    width: 90,
    render: (row: Api.Waf.RuleSubscription) =>
      row.auto_publish
        ? h(NTag, { size: 'small', type: 'warning', bordered: false }, { default: () => '自动' })
        : h(NTag, { size: 'small', bordered: false }, { default: () => '手动' })
  },
  {
    title: '启用',
    key: 'enabled',
    width: 80,
    render: (row: Api.Waf.RuleSubscription) =>
      h(NSwitch, {
        size: 'small',
        value: row.enabled,
        onUpdateValue: (v: boolean) => doToggle(row, v)
      })
  },
  {
    title: '上次同步',
    key: 'last_sync_at',
    width: 200,
    render: (row: Api.Waf.RuleSubscription) =>
      h('span', { class: 'text-xs' }, `${fmtTime(row.last_sync_at)} · ${row.last_count ?? 0} 条`)
  },
  {
    title: '状态',
    key: 'last_status',
    width: 160,
    ellipsis: { tooltip: true },
    render: (row: Api.Waf.RuleSubscription) => {
      const s = row.last_status || '';
      if (!s) return h('span', { class: 'text-[rgb(170,170,170)]' }, '从未同步');
      return s.startsWith('ok')
        ? h(NTag, { size: 'small', type: 'success', bordered: false }, { default: () => s })
        : h(NTag, { size: 'small', type: 'error', bordered: false }, { default: () => s });
    }
  },
  {
    title: '操作',
    key: 'actions',
    width: 220,
    render: (row: Api.Waf.RuleSubscription) =>
      h('div', { class: 'flex gap-2' }, [
        h(
          NButton,
          { size: 'tiny', type: 'primary', secondary: true, loading: syncingId.value === row.id, onClick: () => doSync(row) },
          { default: () => '立即同步' }
        ),
        h(NButton, { size: 'tiny', secondary: true, onClick: () => openEdit(row) }, { default: () => '编辑' }),
        h(
          NPopconfirm,
          { onPositiveClick: () => doDelete(row) },
          {
            trigger: () => h(NButton, { size: 'tiny', type: 'error', secondary: true }, { default: () => '删除' }),
            default: () => '删除订阅将同时清理其同步的规则并重新发布，确认？'
          }
        )
      ])
  }
];

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">规则订阅源</h2>
        <p class="text-sm text-[rgb(125,125,125)]">
          定时拉取远程规则集（JSON 数组，与规则导出格式一致）合并入库；默认同步后需在规则页手动发布
        </p>
      </div>
      <div class="flex gap-2">
        <NButton :loading="loading" @click="load">刷新</NButton>
        <NButton type="primary" @click="openCreate">新建订阅</NButton>
      </div>
    </div>

    <NCard :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="rows" :loading="loading" :bordered="false" size="small">
        <template #empty>
          <NEmpty description="暂无订阅源" />
        </template>
      </NDataTable>
    </NCard>

    <NModal
      v-model:show="showModal"
      preset="card"
      :title="editing ? '编辑订阅' : '新建订阅'"
      class="w-[520px]"
      :mask-closable="false"
    >
      <div class="space-y-3">
        <div>
          <p class="mb-1 text-sm">名称</p>
          <NInput v-model:value="form.name" maxlength="64" show-count placeholder="如：社区规则源" />
        </div>
        <div>
          <p class="mb-1 text-sm">订阅 URL</p>
          <NInput v-model:value="form.url" placeholder="https://example.com/rules.json" />
          <p class="mt-1 text-xs text-[rgb(125,125,125)]">内容为规则 JSON 数组（可在规则页导出后修改）</p>
        </div>
        <div>
          <p class="mb-1 text-sm">同步周期（分钟）</p>
          <NInputNumber v-model:value="form.interval_min" :min="1" class="w-full" :show-button="false" />
        </div>
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm">同步后自动发布</p>
            <p class="text-xs text-[rgb(125,125,125)]">关闭时仅入库，需到规则页手动发布生效</p>
          </div>
          <NSwitch v-model:value="form.auto_publish" />
        </div>
        <div class="flex justify-end gap-2 pt-2">
          <NButton @click="showModal = false">取消</NButton>
          <NButton type="primary" :loading="saving" @click="doSave">保存</NButton>
        </div>
      </div>
    </NModal>
  </div>
</template>
