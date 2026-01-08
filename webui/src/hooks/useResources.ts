import {
  useQuery,
  useMutation,
  useQueryClient,
  UseQueryOptions,
  UseMutationOptions,
} from '@tanstack/react-query';
import { apiClient } from '../services/api';

export interface Resource {
  id: string;
  name: string;
  type: string;
  description?: string;
  created_at?: string;
  updated_at?: string;
  [key: string]: unknown;
}

interface ListResourcesParams {
  page?: number;
  limit?: number;
  search?: string;
  sort?: string;
}

interface ListResourcesResponse {
  data: Resource[];
  total: number;
  page: number;
  limit: number;
}

export function useResources(
  params?: ListResourcesParams,
  options?: UseQueryOptions<ListResourcesResponse>
) {
  return useQuery({
    queryKey: ['resources', params],
    queryFn: async () => {
      const response = await apiClient.get<ListResourcesResponse>(
        '/resources',
        { params }
      );
      return response.data;
    },
    enabled: true,
    ...options,
  });
}

export function useResource(
  id: string | undefined,
  options?: UseQueryOptions<Resource>
) {
  return useQuery({
    queryKey: ['resources', id],
    queryFn: async () => {
      if (!id) throw new Error('Resource ID is required');
      const response = await apiClient.get<Resource>(`/resources/${id}`);
      return response.data;
    },
    enabled: !!id,
    ...options,
  });
}

export function useCreateResource(
  options?: UseMutationOptions<Resource, Error, Omit<Resource, 'id'>>
) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (data) => {
      const response = await apiClient.post<Resource>('/resources', data);
      return response.data;
    },
    onSuccess: (newResource) => {
      queryClient.invalidateQueries({ queryKey: ['resources'] });
      queryClient.setQueryData(['resources', newResource.id], newResource);
    },
    ...options,
  });
}

export function useUpdateResource(
  options?: UseMutationOptions<Resource, Error, { id: string; data: Partial<Resource> }>
) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ id, data }) => {
      const response = await apiClient.put<Resource>(`/resources/${id}`, data);
      return response.data;
    },
    onSuccess: (updatedResource) => {
      queryClient.invalidateQueries({ queryKey: ['resources'] });
      queryClient.setQueryData(['resources', updatedResource.id], updatedResource);
    },
    ...options,
  });
}

export function useDeleteResource(
  options?: UseMutationOptions<void, Error, string>
) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id) => {
      await apiClient.delete(`/resources/${id}`);
    },
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: ['resources'] });
      queryClient.removeQueries({ queryKey: ['resources', id] });
    },
    ...options,
  });
}
