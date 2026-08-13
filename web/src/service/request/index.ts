import type { AxiosResponse } from 'axios';
import { createFlatRequest } from '@sa/axios';
import { useAuthStore } from '@/store/modules/auth';
import { getServiceBaseURL } from '@/utils/service';
import { getAuthorization, showErrorMsg } from './shared';
import type { RequestInstanceState } from './type';

const isHttpProxy = import.meta.env.DEV && import.meta.env.VITE_HTTP_PROXY === 'Y';
const { baseURL } = getServiceBaseURL(import.meta.env, isHttpProxy);

export const request = createFlatRequest<any, any, RequestInstanceState>(
  { baseURL },
  {
    defaultState: {
      errMsgStack: [],
      refreshTokenPromise: null
    } as RequestInstanceState,
    transform(response: AxiosResponse) {
      return response.data;
    },
    async onRequest(config) {
      const Authorization = getAuthorization();
      Object.assign(config.headers, { Authorization });

      return config;
    },
    isBackendSuccess(response) {
      // 后端约定：HTTP 2xx 即成功（返回结构为直接业务数据，无 code 包装）
      return response.status >= 200 && response.status < 300;
    },
    async onBackendFail(response, instance) {
      const authStore = useAuthStore();

      function handleLogout() {
        authStore.resetStore();
      }

      // HTTP 401：登录失效，清除凭证跳转登录
      if (response.status === 401) {
        handleLogout();
        return null;
      }

      const msg = response.data?.error || response.data?.msg || '请求失败';
      showErrorMsg(request.state, msg);

      return null;
    },
    onError(error) {
      let message = error.message;

      if (error.response) {
        // HTTP 401：登录失效，清除凭证跳转登录
        if (error.response.status === 401) {
          const authStore = useAuthStore();
          authStore.resetStore();
          return;
        }

        message = error.response.data?.error || message;
      }

      showErrorMsg(request.state, message);
    }
  }
);
