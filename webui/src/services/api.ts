import axios, { AxiosInstance, AxiosError, AxiosResponse } from 'axios';

interface ApiErrorResponse {
  error?: string;
  message?: string;
  details?: Record<string, unknown>;
  code?: string;
}

interface ApiResponse<T = unknown> {
  data?: T;
  error?: ApiErrorResponse;
  message?: string;
}

class ApiClient {
  private instance: AxiosInstance;

  constructor(baseURL: string = '/api/v1') {
    this.instance = axios.create({
      baseURL,
      headers: {
        'Content-Type': 'application/json',
      },
      timeout: 30000,
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    // Request interceptor for auth token
    this.instance.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('auth_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Response interceptor for error handling
    this.instance.interceptors.response.use(
      (response) => {
        return response;
      },
      (error: AxiosError<ApiErrorResponse>) => {
        if (error.response?.status === 401) {
          // Clear token and redirect to login on unauthorized
          localStorage.removeItem('auth_token');
          localStorage.removeItem('user');
          window.location.href = '/login';
        }

        const message =
          error.response?.data?.message ||
          error.response?.data?.error ||
          error.message ||
          'An error occurred';

        const enrichedError = new Error(message);
        Object.assign(enrichedError, {
          status: error.response?.status,
          code: error.response?.data?.code,
          details: error.response?.data?.details,
        });

        return Promise.reject(enrichedError);
      }
    );
  }

  get<T = unknown>(url: string, config?: any): Promise<AxiosResponse<T>> {
    return this.instance.get<T>(url, config);
  }

  post<T = unknown>(url: string, data?: any, config?: any): Promise<AxiosResponse<T>> {
    return this.instance.post<T>(url, data, config);
  }

  put<T = unknown>(url: string, data?: any, config?: any): Promise<AxiosResponse<T>> {
    return this.instance.put<T>(url, data, config);
  }

  patch<T = unknown>(url: string, data?: any, config?: any): Promise<AxiosResponse<T>> {
    return this.instance.patch<T>(url, data, config);
  }

  delete<T = unknown>(url: string, config?: any): Promise<AxiosResponse<T>> {
    return this.instance.delete<T>(url, config);
  }

  getInstance(): AxiosInstance {
    return this.instance;
  }
}

export const apiClient = new ApiClient();
export type { ApiResponse, ApiErrorResponse };
