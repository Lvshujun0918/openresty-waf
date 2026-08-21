<script setup lang="ts">
import { h, onMounted, ref } from 'vue';
import { NButton, NCard, NDataTable, NForm, NFormItem, NInput, NModal, NPopconfirm, NTag } from 'naive-ui';
import { createToken, fetchTokens, revokeToken } from '@/service/api';

const tokens = ref<Api.Waf.ApiToken[]>([]);
const loading = ref(false);

const showCreateModal = ref(false);
const createName = ref('');
const creating = ref(false);

const showTokenModal = ref(false);
const createdToken = ref<{ name: string; token: string }>({ name: '', token: '' });

function fmtTime(t: string | null) {
  if (!t) return '-';
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '');
}

async function load() {
  loading.value = true;
  try {
    const res = await fetchTokens();
    tokens.value = res.data ?? [];
  } finally {
    loading.value = false;
  }
}

function openCreate() {
  createName.value = '';
  showCreateModal.value = true;
}

async function doCreate() {
  const name = createName.value.trim();
  if (!name) {
    window.$message?.error('请输入 Token 名称');
    return;
  }
  if (name.length > 64) {
    window.$message?.error('名称不能超过 64 个字符');
    return;
  }
  creating.value = true;
  try {
    const res = await createToken({ name });
    if (res.error || !res.data?.token) {
      window.$message?.error('创建失败');
      return;
    }
    createdToken.value = { name: res.data.name, token: res.data.token };
    showCreateModal.value = false;
    showTokenModal.value = true;
    await load();
  } finally {
    creating.value = false;
  }
}

async function copyToken() {
  try {
    await navigator.clipboard.writeText(createdToken.value.token);
    window.$message?.success('已复制到剪贴板');
  } catch {
    window.$message?.error('复制失败，请手动选择复制');
  }
}

async function doRevoke(row: Api.Waf.ApiToken) {
  const res = await revokeToken(row.id);
  if (res.error) {
    window.$message?.error('吊销失败');
    return;
  }
  window.$message?.success(`已吊销 Token「${row.name}」`);
  await load();
}

const columns = [
  { title: 'ID', key: 'id', width: 70 },
  { title: '名称', key: 'name', ellipsis: { tooltip: true } },
  {
    title: '前缀',
    key: 'prefix',
    width: 140,
    render: (row: Api.Waf.ApiToken) => h('span', { class: 'font-mono text-sm' }, `${row.prefix}…`)
  },
  {
    title: '最后使用时间',
    key: 'last_used_at',
    width: 170,
    render: (row: Api.Waf.ApiToken) => h('span', { class: 'text-xs' }, row.last_used_at ? fmtTime(row.last_used_at) : '从未使用')
  },
  {
    title: '状态',
    key: 'revoked_at',
    width: 90,
    render: (row: Api.Waf.ApiToken) =>
      row.revoked_at
        ? h(NTag, { size: 'small', type: 'error', bordered: false }, { default: () => '已吊销' })
        : h(NTag, { size: 'small', type: 'success', bordered: false }, { default: () => '正常' })
  },
  {
    title: '创建时间',
    key: 'created_at',
    width: 170,
    render: (row: Api.Waf.ApiToken) => h('span', { class: 'text-xs' }, fmtTime(row.created_at))
  },
  {
    title: '操作',
    key: 'action',
    width: 100,
    render: (row: Api.Waf.ApiToken) =>
      h(
        NPopconfirm,
        { onPositiveClick: () => doRevoke(row), disabled: !!row.revoked_at },
        {
          trigger: () =>
            h(
              NButton,
              { size: 'small', quaternary: true, type: 'error', disabled: !!row.revoked_at },
              { default: () => '吊销' }
            ),
          default: () => `确认吊销 Token「${row.name}」？吊销后立即失效且不可恢复。`
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
        <h2 class="text-xl font-semibold">API Token 管理</h2>
        <p class="text-sm text-[rgb(125,125,125)]">用于脚本/CI 调用管理接口的长期凭证；明文仅创建时展示一次，请妥善保存</p>
      </div>
      <NButton type="primary" @click="openCreate">新建 Token</NButton>
    </div>

    <NCard :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="tokens" :loading="loading" :bordered="false" size="small" />
    </NCard>

    <NModal v-model:show="showCreateModal" preset="card" title="新建 API Token" style="width: 440px">
      <NForm label-placement="left" label-width="90">
        <NFormItem label="用途备注">
          <NInput v-model:value="createName" maxlength="64" show-count placeholder="如：CI 部署脚本、监控拉取（≤64 字符）" @keyup.enter="doCreate" />
        </NFormItem>
      </NForm>
      <template #footer>
        <div class="flex justify-end gap-2">
          <NButton @click="showCreateModal = false">取消</NButton>
          <NButton type="primary" :loading="creating" @click="doCreate">创建</NButton>
        </div>
      </template>
    </NModal>

    <NModal v-model:show="showTokenModal" preset="card" title="Token 创建成功" style="width: 560px" :mask-closable="false" :closable="false">
      <div class="space-y-3">
        <div class="text-sm">
          Token「{{ createdToken.name }}」已创建。请立即复制并妥善保存：
        </div>
        <div class="flex items-center gap-2">
          <NInput :value="createdToken.token" readonly class="font-mono" @click="copyToken" />
          <NButton type="primary" @click="copyToken">复制</NButton>
        </div>
        <NTag type="warning" :bordered="false">此 Token 仅显示一次，关闭本窗口后将无法再查看</NTag>
      </div>
      <template #footer>
        <div class="flex justify-end">
          <NButton type="primary" @click="showTokenModal = false">我已保存，关闭</NButton>
        </div>
      </template>
    </NModal>
  </div>
</template>
