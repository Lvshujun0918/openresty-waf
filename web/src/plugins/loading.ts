// @unocss-include
import { getColorPalette, getRgb } from '@sa/color';
import { DARK_CLASS } from '@/constants/app';
import { localStg } from '@/utils/storage';
import { toggleHtmlClass } from '@/utils/common';
import { $t } from '@/locales';

export function setupLoading() {
  const themeColor = localStg.get('themeColor') || '#646cff';
  const darkMode = localStg.get('darkMode') || false;
  const palette = getColorPalette(themeColor);

  const { r, g, b } = getRgb(themeColor);

  const primaryColor = `--primary-color: ${r} ${g} ${b}`;

  const svgCssVars = Array.from(palette.entries())
    .map(([key, value]) => `--logo-color-${key}: ${value}`)
    .join(';');

  const cssVars = `${primaryColor}; ${svgCssVars}`;

  if (darkMode) {
    toggleHtmlClass(DARK_CLASS).add();
  }

  const loadingClasses = [
    'left-0 top-0',
    'left-0 bottom-0 animate-delay-500',
    'right-0 top-0 animate-delay-1000',
    'right-0 bottom-0 animate-delay-1500'
  ];

  const dot = loadingClasses
    .map(item => {
      return `<div class="absolute w-16px h-16px bg-primary rounded-8px animate-pulse ${item}"></div>`;
    })
    .join('\n');

  const loading = `
<div class="fixed-center flex-col bg-layout" style="${cssVars}">
  <div class="w-128px h-128px">
    ${getLogoSvg()}
  </div>
  <div class="w-56px h-56px my-36px">
    <div class="relative h-full animate-spin">
      ${dot}
    </div>
  </div>
  <h2 class="text-28px font-500 text-primary">${$t('system.title')}</h2>
</div>`;

  const app = document.getElementById('app');

  if (app) {
    app.innerHTML = loading;
  }
}

function getLogoSvg() {
  const logoSvg = `<svg
        width="100%"
        height="100%"
        viewBox="0 0 32 32"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <linearGradient id="ld-post" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="var(--logo-color-600)" />
            <stop offset="1" stop-color="var(--logo-color-700)" />
          </linearGradient>
          <linearGradient id="ld-bar" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stop-color="var(--logo-color-400)" />
            <stop offset="1" stop-color="var(--logo-color-300)" />
          </linearGradient>
        </defs>
        <!-- 左侧进线（入站流量） -->
        <rect x="3.2" y="7.5" width="4.8" height="3" rx="1.5" fill="var(--logo-color-500)" opacity=".72" />
        <rect x="3.2" y="21.5" width="4.8" height="3" rx="1.5" fill="var(--logo-color-500)" opacity=".72" />
        <!-- 防火门立柱 -->
        <rect x="8.4" y="4.2" width="4.6" height="23.6" rx="2.3" fill="url(#ld-post)" />
        <rect x="20.6" y="4.2" width="4.6" height="23.6" rx="2.3" fill="url(#ld-post)" />
        <!-- 拦截止挡横梁 -->
        <rect x="3.2" y="13.7" width="19.2" height="4.6" rx="2.3" fill="url(#ld-bar)" />
        <!-- 右侧数据流箭头（净化通过） -->
        <path d="M21.8 9.6 L29.6 16 L21.8 22.4 Z" fill="url(#ld-bar)" />
      </svg>
  `;

  return logoSvg;
}
