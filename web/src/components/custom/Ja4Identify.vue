<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { NTag } from 'naive-ui';
import { fetchJa4Lookup } from '@/service/api';

const props = defineProps<{ ja4: string }>();

const result = ref<{ matched: boolean; profile?: { name: string; category: string } }>({ matched: false });
const loaded = ref(false);

const catMeta: Record<string, { label: string; type: 'error' | 'info' | 'warning' | 'default' }> = {
  malware: { label: '恶意', type: 'error' },
  browser: { label: '浏览器', type: 'info' },
  tool: { label: '工具', type: 'warning' },
  other: { label: '其他', type: 'default' }
};

onMounted(async () => {
  if (!props.ja4) return;
  try {
    const res = await fetchJa4Lookup(props.ja4);
    result.value = res.data ?? { matched: false };
  } catch {
    /* 查询失败静默 */
  }
  loaded.value = true;
});
</script>

<template>
  <span v-if="loaded && result.matched && result.profile" class="inline-flex items-center gap-1">
    <NTag size="tiny" :bordered="false" :type="catMeta[result.profile.category]?.type || 'default'">
      {{ catMeta[result.profile.category]?.label || result.profile.category }}
    </NTag>
    <span class="text-[11px] text-[rgb(125,125,125)]">{{ result.profile.name }}</span>
  </span>
  <NTag v-else-if="loaded && ja4" size="tiny" bordered class="!text-[11px]">未知</NTag>
</template>
