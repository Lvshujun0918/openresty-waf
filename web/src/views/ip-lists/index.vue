<script setup lang="ts">
import { h, onMounted, reactive, ref } from 'vue';
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
  NSelect,
  NSpace,
  NSwitch,
  NTag
} from 'naive-ui';
import { createIpListSub, deleteIpListSub, fetchIpListSubs, setIpListSubEnabled, syncIpListSub, updateIpListSub } from '@/service/api';

const subs = ref<Api.Waf.IpListSub[]>([]);
const loading = ref(false);

async function load() {
  loading.value = true;
  try {
    const res = await fetchIpListSubs();
    subs.value = res.data ?? [];
  } finally {
    loading.value = false;
  }
}

async function toggleEnabled(row: Api.Waf.IpListSub) {
  await setIpListSubEnabled(row.id, !row.enabled);
  row.enabled = !row.enabled;
  window.$message?.success('已更新');
}

async function remove(row: Api.Waf.IpListSub) {
  await deleteIpListSub(row.id);
  window.$message?.success('已删除');
  await load();
}

async function doSync(row: Api.Waf.IpListSub) {
  const res = await syncIpListSub(row.id);
  window.$message?.success(`同步完成，拉取 ${res.data?.count ?? 0} 条`);
  await load();
}

// —— 表单 ——
const editOpen = ref(false);
const saving = ref(false);
const form = reactive<Partial<Api.Waf.IpListSub>>({ name: '', url: '', type: 'blacklist', interval_min: 60, enabled: true });

function openCreate() {
  Object.assign(form, { id: undefined, name: '', url: '', type: 'blacklist', interval_min: 60, enabled: true });
  editOpen.value = true;
}
function openEdit(row: Api.Waf.IpListSub) {
  Object.assign(form, row);
  editOpen.value = true;
}
async function save() {
  saving.value = true;
  try {
    if (form.id) {
      await updateIpListSub(form.id, form);
    } else {
      await createIpListSub(form);
    }
    window.$message?.success('已保存');
    editOpen.value = false;
    await load();
  } finally {
    saving.value = false;
  }
}

const columns = [
  { title: '名称', key: 'name', minWidth: 140 },
  { title: '类型', key: 'type', width: 90, render: (row: Api.Waf.IpListSub) => h(NTag, { size: 'small', type: row.type === 'whitelist' ? 'success' : 'error', bordered: false }, { default: () => (row.type === 'whitelist' ? '白名单' : '黑名单') }) },
  { title: '订阅 URL', key: 'url', minWidth: 200, ellipsis: { tooltip: true } },
  { title: '同步周期(min)', key: 'interval_min', width: 110 },
  { title: '同步状态', key: 'last_status', width: 100, render: (row: Api.Waf.IpListSub) => row.last_status || '-' },
  { title: '条数', key: 'last_count', width: 70, render: (row: Api.Waf.IpListSub) => row.last_count ?? '-' },
  {
    title: '启用',
    key: 'enabled',
    width: 70,
    render: (row: Api.Waf.IpListSub) => h(NSwitch, { value: row.enabled, onUpdateValue: () => toggleEnabled(row) })
  },
  {
    title: '操作',
    key: 'action',
    width: 200,
    render: (row: Api.Waf.IpListSub) =>
      h(NSpace, { size: 4 }, [
        h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => doSync(row) }, { default: () => '同步' }),
        h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openEdit(row) }, { default: () => '编辑' }),
        h(
          NPopconfirm,
          { onPositiveClick: () => remove(row) },
          {
            trigger: () => h(NButton, { size: 'small', quaternary: true, type: 'error' }, { default: () => '删除' }),
            default: () => '确认删除该订阅？'
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
        <h2 class="text-xl font-semibold">黑白名单</h2>
        <p class="text-sm text-[rgb(125,125,125)]">订阅远程威胁情报 IP 列表，定期自动同步</p>
      </div>
      <NButton type="primary" @click="openCreate">新建订阅</NButton>
    </div>

    <NCard :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="subs" :loading="loading" :bordered="false" size="small" />
    </NCard>

    <NModal v-model:show="editOpen" preset="card" :title="form.id ? '编辑订阅' : '新建订阅'" class="w-[min(96vw,560px)]">
      <NForm :model="form" label-placement="left" label-width="100">
        <NFormItem label="名称" required>
          <NInput v-model:value="form.name" placeholder="如 恶意 IP 情报组" />
        </NFormItem>
        <NFormItem label="类型" required>
          <NSelect v-model:value="form.type" :options="[{ label: '白名单', value: 'whitelist' }, { label: '黑名单', value: 'blacklist' }]" />
        </NFormItem>
        <NFormItem label="订阅 URL" required>
          <NInput v-model:value="form.url" placeholder="https://example.com/ips.txt（每行一个 IP/CIDR）" />
        </NFormItem>
        <NFormItem label="同步周期(min)">
          <NInputNumber v-model:value="form.interval_min" :min="5" />
        </NFormItem>
        <NFormItem label="启用">
          <NSwitch v-model:value="form.enabled" />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="editOpen = false">取消</NButton>
          <NButton type="primary" :loading="saving" @click="save">保存</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>
