<template>
  <div class="app-logo">
    <svg width="100%" height="100%" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="gl-inlet" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stop-color="rgb(var(--primary-500-color))" stop-opacity=".3" />
          <stop offset="1" stop-color="rgb(var(--primary-500-color))" stop-opacity=".72" />
        </linearGradient>
        <linearGradient id="gl-post" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stop-color="rgb(var(--primary-600-color))" />
          <stop offset="1" stop-color="rgb(var(--primary-700-color))" />
        </linearGradient>
        <linearGradient id="gl-bar" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stop-color="rgb(var(--primary-400-color))" />
          <stop offset="1" stop-color="rgb(var(--primary-300-color))" />
        </linearGradient>
      </defs>
      <!-- 左侧进线（入站流量） -->
      <rect x="3.2" y="7.5" width="4.8" height="3" rx="1.5" fill="url(#gl-inlet)" />
      <rect x="3.2" y="21.5" width="4.8" height="3" rx="1.5" fill="url(#gl-inlet)" />
      <!-- 防火门立柱 -->
      <rect x="8.4" y="4.2" width="4.6" height="23.6" rx="2.3" fill="url(#gl-post)" />
      <rect x="20.6" y="4.2" width="4.6" height="23.6" rx="2.3" fill="url(#gl-post)" />
      <!-- 拦截止挡横梁 -->
      <rect x="3.2" y="13.7" width="19.2" height="4.6" rx="2.3" fill="url(#gl-bar)" />
      <!-- 右侧数据流箭头（净化通过） -->
      <path d="M21.8 9.6 L29.6 16 L21.8 22.4 Z" fill="url(#gl-bar)" />
    </svg>
  </div>
</template>

<style scoped>
.app-logo {
  --logo-color-300: rgb(var(--primary-300-color));
  --logo-color-400: rgb(var(--primary-400-color));
  --logo-color-500: rgb(var(--primary-500-color));
  --logo-color-600: rgb(var(--primary-600-color));
  --logo-color-700: rgb(var(--primary-700-color));
}
</style>
