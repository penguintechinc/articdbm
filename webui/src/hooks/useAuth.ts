import {
  useQuery,
  useMutation,
  useQueryClient,
  UseQueryOptions,
  UseMutationOptions,
} from '@tanstack/react-query';
import { apiClient } from '../services/api';

export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  avatar_url?: string;
  created_at?: string;
  last_login?: string;
  [key: string]: unknown;
}

export interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

interface LoginCredentials {
  email: string;
  password: string;
}

interface LoginResponse {
  user: User;
  token: string;
  expires_at?: string;
}

interface LogoutResponse {
  success: boolean;
  message?: string;
}

export function useAuth(options?: UseQueryOptions<User | null>) {
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['auth', 'user'],
    queryFn: async () => {
      try {
        const response = await apiClient.get<User>('/auth/me');
        return response.data;
      } catch (error) {
        // If unauthorized, return null instead of throwing
        if ((error as any).status === 401) {
          return null;
        }
        throw error;
      }
    },
    enabled: true,
    staleTime: 5 * 60 * 1000, // 5 minutes
    gcTime: 10 * 60 * 1000, // 10 minutes (formerly cacheTime)
    ...options,
  });

  return {
    user: query.data,
    isAuthenticated: !!query.data,
    isLoading: query.isLoading,
    isError: query.isError,
    error: query.error,
    refetch: query.refetch,
  };
}

export function useLogin(
  options?: UseMutationOptions<LoginResponse, Error, LoginCredentials>
) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (credentials) => {
      const response = await apiClient.post<LoginResponse>('/auth/login', credentials);
      return response.data;
    },
    onSuccess: (data) => {
      localStorage.setItem('auth_token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      queryClient.setQueryData(['auth', 'user'], data.user);
      queryClient.invalidateQueries({ queryKey: ['auth'] });
    },
    onError: () => {
      localStorage.removeItem('auth_token');
      localStorage.removeItem('user');
    },
    ...options,
  });
}

export function useLogout(
  options?: UseMutationOptions<LogoutResponse, Error, void>
) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async () => {
      const response = await apiClient.post<LogoutResponse>('/auth/logout');
      return response.data;
    },
    onSuccess: () => {
      localStorage.removeItem('auth_token');
      localStorage.removeItem('user');
      queryClient.setQueryData(['auth', 'user'], null);
      queryClient.invalidateQueries({ queryKey: ['auth'] });
    },
    onSettled: () => {
      localStorage.removeItem('auth_token');
      localStorage.removeItem('user');
    },
    ...options,
  });
}

export function useSignUp(
  options?: UseMutationOptions<LoginResponse, Error, { email: string; password: string; name: string }>
) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (data) => {
      const response = await apiClient.post<LoginResponse>('/auth/signup', data);
      return response.data;
    },
    onSuccess: (data) => {
      localStorage.setItem('auth_token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      queryClient.setQueryData(['auth', 'user'], data.user);
    },
    onError: () => {
      localStorage.removeItem('auth_token');
      localStorage.removeItem('user');
    },
    ...options,
  });
}

export function useRefreshToken(
  options?: UseMutationOptions<LoginResponse, Error, void>
) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async () => {
      const response = await apiClient.post<LoginResponse>('/auth/refresh');
      return response.data;
    },
    onSuccess: (data) => {
      localStorage.setItem('auth_token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      queryClient.setQueryData(['auth', 'user'], data.user);
    },
    ...options,
  });
}
