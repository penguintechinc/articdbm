import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/common/Card';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { Alert, AlertDescription } from '@/components/common/Alert';
import { AlertCircle, CheckCircle2, Play, Trash2, Plus, Code } from 'lucide-react';
import { apiClient } from '@/services/api';

interface TrinoCatalog {
  name: string;
  connector: string;
  properties: Record<string, string>;
}

interface TrinoCluster {
  id: string;
  name: string;
  status: 'running' | 'stopped' | 'error';
  coordinatorUrl: string;
  workers: number;
  catalogs: TrinoCatalog[];
  createdAt: string;
}

interface QueryResult {
  columns: string[];
  rows: any[][];
  executionTimeMs: number;
}

async function fetchTrinoClusters(): Promise<TrinoCluster[]> {
  const response = await apiClient.get<{ data: TrinoCluster[] }>('/trino');
  return response.data?.data || [];
}

async function createTrinoCluster(data: any): Promise<TrinoCluster> {
  const response = await apiClient.post<{ data: TrinoCluster }>('/trino', data);
  return response.data?.data || data;
}

async function executeQuery(clusterId: string, query: string): Promise<QueryResult> {
  const response = await apiClient.post<{ data: QueryResult }>(
    `/trino/${clusterId}/query`,
    { query }
  );
  return response.data?.data || { columns: [], rows: [], executionTimeMs: 0 };
}

async function deleteTrinoCluster(clusterId: string): Promise<void> {
  await apiClient.delete(`/trino/${clusterId}`);
}

export default function TrinoPage() {
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [selectedClusterId, setSelectedClusterId] = useState<string | null>(null);
  const [query, setQuery] = useState('SELECT 1;');
  const [formData, setFormData] = useState({
    name: '',
    workers: '3',
  });
  const [error, setError] = useState<string | null>(null);

  const queryClient = useQueryClient();

  const { data: clusters, isLoading } = useQuery({
    queryKey: ['trino', 'clusters'],
    queryFn: fetchTrinoClusters,
    refetchInterval: 30000,
  });

  const createMutation = useMutation({
    mutationFn: (data) => createTrinoCluster(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trino', 'clusters'] });
      setShowCreateForm(false);
      setFormData({ name: '', workers: '3' });
      setError(null);
    },
    onError: (err: any) => {
      setError(err.message || 'Failed to create cluster');
    },
  });

  const queryMutation = useMutation({
    mutationFn: () => executeQuery(selectedClusterId || '', query),
    onError: (err: any) => {
      setError(err.message || 'Failed to execute query');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (clusterId: string) => deleteTrinoCluster(clusterId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trino', 'clusters'] });
      setSelectedClusterId(null);
      setError(null);
    },
    onError: (err: any) => {
      setError(err.message || 'Failed to delete cluster');
    },
  });

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate(formData);
  };

  const selectedCluster = clusters?.find((c) => c.id === selectedClusterId);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'text-green-600 bg-green-50';
      case 'stopped':
        return 'text-gray-600 bg-gray-50';
      case 'error':
        return 'text-red-600 bg-red-50';
      default:
        return 'text-gray-600 bg-gray-50';
    }
  };

  const getStatusIcon = (status: string) => {
    if (status === 'running') return <CheckCircle2 className="h-4 w-4" />;
    if (status === 'error') return <AlertCircle className="h-4 w-4" />;
    return <div className="h-4 w-4 rounded-full bg-gray-400" />;
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold">Trino Clusters</h1>
          <p className="text-gray-600 mt-2">SQL query engine for analytics across data sources</p>
        </div>
        <Button
          onClick={() => setShowCreateForm(!showCreateForm)}
          className="gap-2"
        >
          <Plus className="h-4 w-4" />
          New Cluster
        </Button>
      </div>

      {/* Error Alert */}
      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Create Cluster Form */}
      {showCreateForm && (
        <Card>
          <CardHeader>
            <CardTitle>Create New Trino Cluster</CardTitle>
            <CardDescription>Configure cluster resources and settings</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleCreateSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-900 mb-2">
                  Cluster Name
                </label>
                <Input
                  type="text"
                  placeholder="my-trino-cluster"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-900 mb-2">
                  Number of Workers
                </label>
                <Input
                  type="number"
                  value={formData.workers}
                  onChange={(e) => setFormData({ ...formData, workers: e.target.value })}
                  min="1"
                  required
                />
              </div>

              <div className="flex gap-2 pt-4">
                <Button
                  type="submit"
                  disabled={createMutation.isPending}
                >
                  {createMutation.isPending ? 'Creating...' : 'Create Cluster'}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowCreateForm(false)}
                >
                  Cancel
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Clusters List */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle>Clusters</CardTitle>
              <CardDescription>Select a cluster to query</CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <p className="text-sm text-gray-600">Loading clusters...</p>
              ) : !clusters || clusters.length === 0 ? (
                <p className="text-sm text-gray-600">No clusters found</p>
              ) : (
                <div className="space-y-2">
                  {clusters.map((cluster) => (
                    <div
                      key={cluster.id}
                      className={`p-3 rounded-lg border cursor-pointer transition-all ${
                        selectedClusterId === cluster.id
                          ? 'border-blue-600 bg-blue-50'
                          : 'border-gray-200 hover:border-gray-300'
                      }`}
                      onClick={() => {
                        setSelectedClusterId(cluster.id);
                        setError(null);
                      }}
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-sm">{cluster.name}</p>
                          <p className="text-xs text-gray-600">Workers: {cluster.workers}</p>
                        </div>
                        <div className={`flex items-center gap-1 ${getStatusColor(cluster.status)}`}>
                          {getStatusIcon(cluster.status)}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Query Editor & Results */}
        <div className="lg:col-span-2 space-y-4">
          {selectedCluster ? (
            <>
              {/* Cluster Info */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">{selectedCluster.name}</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div>
                      <p className="text-xs text-gray-600">Coordinator URL</p>
                      <p className="text-sm font-medium truncate">{selectedCluster.coordinatorUrl}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-600">Workers</p>
                      <p className="text-sm font-medium">{selectedCluster.workers}</p>
                    </div>
                  </div>

                  {/* Catalogs */}
                  {selectedCluster.catalogs && selectedCluster.catalogs.length > 0 && (
                    <div>
                      <p className="text-sm font-medium mb-2">Connected Catalogs</p>
                      <div className="space-y-1">
                        {selectedCluster.catalogs.map((catalog) => (
                          <div key={catalog.name} className="flex items-center justify-between text-sm">
                            <span className="font-medium">{catalog.name}</span>
                            <span className="text-gray-600 text-xs bg-gray-100 px-2 py-1 rounded">
                              {catalog.connector}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <Button
                    variant="outline"
                    size="sm"
                    className="text-red-600 hover:text-red-700 gap-2 w-full mt-4"
                    onClick={() => deleteMutation.mutate(selectedCluster.id)}
                    disabled={deleteMutation.isPending}
                  >
                    <Trash2 className="h-4 w-4" />
                    Delete Cluster
                  </Button>
                </CardContent>
              </Card>

              {/* Query Editor */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Query Editor</CardTitle>
                  <CardDescription>Execute SQL queries on this cluster</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <textarea
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                      placeholder="SELECT * FROM system.runtime.nodes;"
                      className="w-full h-32 p-3 border border-gray-300 rounded-md font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <Button
                      onClick={() => queryMutation.mutate()}
                      disabled={queryMutation.isPending || selectedCluster.status !== 'running'}
                      className="gap-2 w-full"
                    >
                      <Play className="h-4 w-4" />
                      {queryMutation.isPending ? 'Executing...' : 'Execute Query'}
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Results */}
              {queryMutation.data && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Results</CardTitle>
                    <CardDescription>
                      {queryMutation.data.executionTimeMs}ms | {queryMutation.data.rows.length} rows
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {queryMutation.data.rows.length === 0 ? (
                      <p className="text-sm text-gray-600 text-center py-4">No results</p>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead className="bg-gray-50 border-b">
                            <tr>
                              {queryMutation.data.columns.map((col) => (
                                <th key={col} className="px-3 py-2 text-left font-medium text-gray-900">
                                  {col}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {queryMutation.data.rows.slice(0, 50).map((row, idx) => (
                              <tr key={idx} className="border-b hover:bg-gray-50">
                                {row.map((cell, cellIdx) => (
                                  <td
                                    key={cellIdx}
                                    className="px-3 py-2 text-gray-700 font-mono text-xs"
                                  >
                                    {String(cell)}
                                  </td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        {queryMutation.data.rows.length > 50 && (
                          <p className="text-xs text-gray-600 mt-2">
                            Showing first 50 of {queryMutation.data.rows.length} rows
                          </p>
                        )}
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}
            </>
          ) : (
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-center py-12 text-center">
                  <div>
                    <Code className="h-12 w-12 text-gray-400 mx-auto mb-3" />
                    <p className="text-gray-600">Select a cluster to query</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
