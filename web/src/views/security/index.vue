<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { NAlert, NButton, NCard, NInput, NSpace, NTag } from 'naive-ui';
import { confirmTotp, disableTotp, fetchGetUserInfo, setupTotp } from '@/service/api';

const totpEnabled = ref(false);
const loading = ref(false);
const secret = ref('');
const otpauthUrl = ref('');
const confirmCode = ref('');
const disableCode = ref('');

async function load() {
  loading.value = true;
  try {
    const res = await fetchGetUserInfo();
    const info = res.data as unknown as { totp_enabled?: boolean } | null;
    totpEnabled.value = Boolean(info?.totp_enabled);
  } finally {
    loading.value = false;
  }
}

async function doSetup() {
  const res = await setupTotp();
  secret.value = res.data?.secret ?? '';
  otpauthUrl.value = res.data?.otpauth_url ?? '';
  confirmCode.value = '';
}

async function doConfirm() {
  await confirmTotp(confirmCode.value);
  window.$message?.success('动态验证码已启用，下次登录需要输入 6 位验证码');
  secret.value = '';
  otpauthUrl.value = '';
  confirmCode.value = '';
  await load();
}

async function doDisable() {
  await disableTotp(disableCode.value);
  window.$message?.success('动态验证码已关闭');
  disableCode.value = '';
  await load();
}

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <div>
      <h2 class="text-xl font-semibold">账号安全</h2>
      <p class="text-sm text-[rgb(125,125,125)]">登录防护：TOTP 动态验证码双因子认证</p>
    </div>

    <NCard :bordered="false" class="card-wrapper" title="双因子认证（TOTP）">
      <template #header-extra>
        <NTag :type="totpEnabled ? 'success' : 'default'" size="small" bordered>
          {{ totpEnabled ? '已启用' : '未启用' }}
        </NTag>
      </template>

      <NAlert type="warning" class="mb-4">
        启用后每次登录都需要输入验证器（Google Authenticator / Microsoft Authenticator 等）中的 6 位动态验证码。请妥善保存恢复方式，验证码丢失将无法登录。
      </NAlert>

      <template v-if="!totpEnabled">
        <NSpace vertical>
          <div>
            <NButton type="primary" :loading="loading" @click="doSetup">生成密钥</NButton>
            <span class="ml-2 text-xs text-[rgb(125,125,125)]">使用验证器 App 扫码或手动输入密钥后，输入一次动态码确认启用</span>
          </div>
          <template v-if="secret">
            <div class="rounded bg-[rgb(245,245,245)] px-4 py-3">
              <p class="text-xs text-[rgb(125,125,125)]">密钥（手动输入验证器）</p>
              <p class="mt-1 select-all break-all font-mono text-sm">{{ secret }}</p>
              <p class="mt-2 text-xs text-[rgb(125,125,125)]">otpauth 链接（可导入验证器）</p>
              <p class="mt-1 select-all break-all font-mono text-xs">{{ otpauthUrl }}</p>
            </div>
            <NSpace>
              <NInput v-model:value="confirmCode" maxlength="6" placeholder="输入 6 位动态验证码" class="w-56" />
              <NButton type="primary" :disabled="!confirmCode" @click="doConfirm">确认启用</NButton>
            </NSpace>
          </template>
        </NSpace>
      </template>

      <template v-else>
        <NSpace>
          <NInput v-model:value="disableCode" maxlength="6" placeholder="输入当前 6 位动态验证码" class="w-56" />
          <NButton type="error" secondary :disabled="!disableCode" @click="doDisable">关闭双因子</NButton>
        </NSpace>
      </template>
    </NCard>

    <NCard :bordered="false" class="card-wrapper" title="登录防爆破">
      <p class="text-sm text-[rgb(80,80,80)]">
        连续 5 次登录失败（密码或验证码错误）将锁定账号 15 分钟，锁定期间即使密码正确也无法登录。
      </p>
    </NCard>
  </div>
</template>
