import {
  useQuery,
  useMutation,
  useQueryClient,
  UseQueryOptions,
  UseMutationOptions,
} from '@tanstack/react-query';
import { apiClient } from '../services/api';

export interface Application {
  id: string;
  name: string;
  description?: string;
  status: 'active' | 'inactive' | 'paused';
  api_key?: string;
  api_key_last_4?: string;
  rate_limit?: number;
  webhook_url?: string;
  created_at?: string;
  updated_at?: string;
  [key: string]: unknown;
}

interface ListApplicationsParams {
  page?: number;
  limit?: number;
  search?: string;
  status?: 'active' | 'inactive' | 'paused';
  sort?: string;
}

interface ListApplicationsResponse {
  data: Application[];
  total: number;
  page: number;
  limit: number;
}

export function useApplications(
  params?: ListApplicationsParams,
  options?: UseQueryOptions<ListApplicationsResponse>
) {
  return useQuery({
    queryKey: ['applications', params],
    queryFn: async () => {
      const response = await apiClient.get<ListApplicationsResponse>(
        '/applications',
        { params }
      );
      return response.data;
    },
    enabled: true,
    ...options,
  });
}

export function useApplication(
  id: string | undefined,
  options?: UseQueryOptions<Application>
) {
  return useQuery({
    queryKey: ['applications', id],
    queryFn: async () => {
      if (!id) throw new Error('Application ID is required');
      const response = await apiClient.get<Application>(`/applications/${id}`);
      return response.data;
    },
    enabled: !!id,
    ...options,
  });
}

export function useCreateApplication(
  options?: UseMutationOptions<Application, Error, Omit<Application, 'id'>>
) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (data) => {
      const response = await apiClient.post<Application>('/applications', data);
      return response.data;
    },
    onSuccess: (newApplication) => {
      queryClient.invalidateQueries({ queryKey: ['applications'] });
      queryClient.setQueryData(['applications', newApplication.id], newApplication);
    },
    ...options,
  });
}

export function useUpdateApplication(
  options?: UseMutationOptions<Application, Error, { id: string; data: Partial<Application> }>
) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ id, data }) => {
      const response = await apiClient.put<Application>(`/applications/${id}`, data);
      return response.data;
    },
    onSuccess: (updatedApplication) => {
      queryClient.invalidateQueries({ queryKey: ['applications'] });
      queryClient.setQueryData(['applications', updatedApplication.id], updatedApplication);
    },
    ...options,
  });
}

export function useDeleteApplication(
  options?: UseMutationOptions<void, Error, string>
) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id) => {
      await apiClient.delete(`/applications/${id}`);
    },
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: ['applications'] });
      queryClient.removeQueries({ queryKey: ['applications', id] });
    },
    ...options,
  });
}
