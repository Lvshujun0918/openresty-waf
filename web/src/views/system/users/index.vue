<script setup lang="ts">
import { h, onMounted, reactive, ref } from 'vue';
import { NButton, NCard, NDataTable, NForm, NFormItem, NInput, NModal, NPopconfirm, NSelect, NTag } from 'naive-ui';
import { createUser, deleteUser, fetchUsers, updateUser } from '@/service/api';
import { useAuthStore } from '@/store/modules/auth';

const authStore = useAuthStore();

const users = ref<Api.Waf.UserRow[]>([]);
const loading = ref(false);

const roleOptions = [
  { label: '超管（全部权限）', value: 'super' },
  { label: '运营（业务读写）', value: 'ops' },
  { label: '只读（仅查看）', value: 'viewer' }
];

const roleTagType: Record<string, 'error' | 'info' | 'default'> = {
  super: 'error',
  ops: 'info',
  viewer: 'default'
};

const roleLabel: Record<string, string> = {
  super: '超管',
  ops: '运营',
  viewer: '只读'
};

function fmtTime(t: string | null) {
  if (!t) return '-';
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '');
}

async function load() {
  loading.value = true;
  try {
    const res = await fetchUsers();
    users.value = res.data ?? [];
  } finally {
    loading.value = false;
  }
}

// ---------- 新建 ----------
const showCreateModal = ref(false);
const creating = ref(false);
const createForm = reactive({ username: '', password: '', role: 'viewer' });

function openCreate() {
  createForm.username = '';
  createForm.password = '';
  createForm.role = 'viewer';
  showCreateModal.value = true;
}

async function doCreate() {
  const username = createForm.username.trim();
  if (!username) {
    window.$message?.error('请输入用户名');
    return;
  }
  if (createForm.password.length < 8) {
    window.$message?.error('密码至少 8 位');
    return;
  }
  creating.value = true;
  try {
    const res = await createUser({ username, password: createForm.password, role: createForm.role });
    if (res.error) {
      window.$message?.error('创建失败（用户名可能已存在）');
      return;
    }
    window.$message?.success(`已创建用户「${username}」`);
    showCreateModal.value = false;
    await load();
  } finally {
    creating.value = false;
  }
}

// ---------- 编辑 ----------
const showEditModal = ref(false);
const saving = ref(false);
const editForm = reactive<{ id: number; username: string; role: string; password: string }>({
  id: 0,
  username: '',
  role: 'viewer',
  password: ''
});

function openEdit(row: Api.Waf.UserRow) {
  editForm.id = row.id;
  editForm.username = row.username;
  editForm.role = row.role;
  editForm.password = '';
  showEditModal.value = true;
}

async function doEdit() {
  const payload: { role?: string; password?: string } = { role: editForm.role };
  if (editForm.password) {
    if (editForm.password.length < 8) {
      window.$message?.error('新密码至少 8 位');
      return;
    }
    payload.password = editForm.password;
  }
  saving.value = true;
  try {
    const res = await updateUser(editForm.id, payload);
    if (res.error) {
      window.$message?.error('保存失败（至少保留一个超管）');
      return;
    }
    window.$message?.success(`已保存用户「${editForm.username}」`);
    showEditModal.value = false;
    await load();
  } finally {
    saving.value = false;
  }
}

// ---------- 删除 ----------
async function doDelete(row: Api.Waf.UserRow) {
  const res = await deleteUser(row.id);
  if (res.error) {
    window.$message?.error('删除失败（不能删除自己或最后一个超管）');
    return;
  }
  window.$message?.success(`已删除用户「${row.username}」`);
  await load();
}

const columns = [
  { title: 'ID', key: 'id', width: 70 },
  { title: '用户名', key: 'username', ellipsis: { tooltip: true } },
  {
    title: '角色',
    key: 'role',
    width: 100,
    render: (row: Api.Waf.UserRow) =>
      h(NTag, { size: 'small', type: roleTagType[row.role] ?? 'default', bordered: false }, { default: () => roleLabel[row.role] ?? row.role })
  },
  {
    title: 'TOTP',
    key: 'totp_enabled',
    width: 90,
    render: (row: Api.Waf.UserRow) =>
      row.totp_enabled
        ? h(NTag, { size: 'small', type: 'success', bordered: false }, { default: () => '已启用' })
        : h(NTag, { size: 'small', bordered: false }, { default: () => '未启用' })
  },
  {
    title: '创建时间',
    key: 'created_at',
    width: 170,
    render: (row: Api.Waf.UserRow) => h('span', { class: 'text-xs' }, fmtTime(row.created_at))
  },
  {
    title: '操作',
    key: 'action',
    width: 140,
    render: (row: Api.Waf.UserRow) =>
      h('div', { class: 'flex gap-1' }, [
        h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openEdit(row) }, { default: () => '编辑' }),
        h(
          NPopconfirm,
          { onPositiveClick: () => doDelete(row), disabled: row.username === authStore.userInfo.userName },
          {
            trigger: () =>
              h(
                NButton,
                { size: 'small', quaternary: true, type: 'error', disabled: row.username === authStore.userInfo.userName },
                { default: () => '删除' }
              ),
            default: () => `确认删除用户「${row.username}」？删除后立即无法登录。`
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
        <h2 class="text-xl font-semibold">用户管理</h2>
        <p class="text-sm text-[rgb(125,125,125)]">管理后台账号与角色：超管（全部权限）/ 运营（业务读写）/ 只读（仅查看）</p>
      </div>
      <NButton type="primary" @click="openCreate">新建用户</NButton>
    </div>

    <NCard :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="users" :loading="loading" :bordered="false" size="small" />
    </NCard>

    <NModal v-model:show="showCreateModal" preset="card" title="新建用户" style="width: 440px">
      <NForm label-placement="left" label-width="90">
        <NFormItem label="用户名">
          <NInput v-model:value="createForm.username" maxlength="64" placeholder="登录用户名" @keyup.enter="doCreate" />
        </NFormItem>
        <NFormItem label="密码">
          <NInput
            v-model:value="createForm.password"
            type="password"
            show-password-on="click"
            placeholder="至少 8 位"
            @keyup.enter="doCreate"
          />
        </NFormItem>
        <NFormItem label="角色">
          <NSelect v-model:value="createForm.role" :options="roleOptions" />
        </NFormItem>
      </NForm>
      <template #footer>
        <div class="flex justify-end gap-2">
          <NButton @click="showCreateModal = false">取消</NButton>
          <NButton type="primary" :loading="creating" @click="doCreate">创建</NButton>
        </div>
      </template>
    </NModal>

    <NModal v-model:show="showEditModal" preset="card" :title="`编辑用户「${editForm.username}」`" style="width: 440px">
      <NForm label-placement="left" label-width="90">
        <NFormItem label="角色">
          <NSelect v-model:value="editForm.role" :options="roleOptions" />
        </NFormItem>
        <NFormItem label="重置密码">
          <NInput
            v-model:value="editForm.password"
            type="password"
            show-password-on="click"
            placeholder="留空则不修改；填写则重置（至少 8 位）"
            @keyup.enter="doEdit"
          />
        </NFormItem>
      </NForm>
      <template #footer>
        <div class="flex justify-end gap-2">
          <NButton @click="showEditModal = false">取消</NButton>
          <NButton type="primary" :loading="saving" @click="doEdit">保存</NButton>
        </div>
      </template>
    </NModal>
  </div>
</template>
