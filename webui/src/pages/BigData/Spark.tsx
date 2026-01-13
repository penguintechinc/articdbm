import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/common/Card';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { Alert, AlertDescription } from '@/components/common/Alert';
import { AlertCircle, CheckCircle2, Play, Square, Trash2, Plus } from 'lucide-react';
import { apiClient } from '@/services/api';

interface SparkCluster {
  id: string;
  name: string;
  status: 'running' | 'stopped' | 'error';
  masterUrl: string;
  workers: number;
  memoryPerWorker: string;
  coresPerWorker: number;
  createdAt: string;
}

async function fetchSparkClusters(): Promise<SparkCluster[]> {
  const response = await apiClient.get<{ data: SparkCluster[] }>('/spark');
  return response.data?.data || [];
}

async function createSparkCluster(data: any): Promise<SparkCluster> {
  const response = await apiClient.post<{ data: SparkCluster }>('/spark', data);
  return response.data?.data || data;
}

async function submitSparkJob(clusterId: string, jobData: any): Promise<any> {
  const response = await apiClient.post(`/spark/${clusterId}/jobs`, jobData);
  return response.data;
}

async function deleteSparkCluster(clusterId: string): Promise<void> {
  await apiClient.delete(`/spark/${clusterId}`);
}

export default function SparkPage() {
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [showJobForm, setShowJobForm] = useState<string | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    workers: '3',
    memoryPerWorker: '4g',
    coresPerWorker: '2',
  });
  const [jobData, setJobData] = useState({
    jarUrl: '',
    mainClass: '',
    args: '',
  });
  const [error, setError] = useState<string | null>(null);

  const queryClient = useQueryClient();

  const { data: clusters, isLoading } = useQuery({
    queryKey: ['spark', 'clusters'],
    queryFn: fetchSparkClusters,
    refetchInterval: 30000,
  });

  const createMutation = useMutation({
    mutationFn: (data) => createSparkCluster(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['spark', 'clusters'] });
      setShowCreateForm(false);
      setFormData({ name: '', workers: '3', memoryPerWorker: '4g', coresPerWorker: '2' });
      setError(null);
    },
    onError: (err: any) => {
      setError(err.message || 'Failed to create cluster');
    },
  });

  const jobMutation = useMutation({
    mutationFn: (data: any) => submitSparkJob(data.clusterId, data.job),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['spark', 'clusters'] });
      setShowJobForm(null);
      setJobData({ jarUrl: '', mainClass: '', args: '' });
      setError(null);
    },
    onError: (err: any) => {
      setError(err.message || 'Failed to submit job');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (clusterId: string) => deleteSparkCluster(clusterId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['spark', 'clusters'] });
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

  const handleJobSubmit = (clusterId: string) => (e: React.FormEvent) => {
    e.preventDefault();
    jobMutation.mutate({ clusterId, job: jobData });
  };

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
    return <Square className="h-4 w-4" />;
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold">Spark Clusters</h1>
          <p className="text-gray-600 mt-2">Manage and monitor Apache Spark clusters</p>
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
            <CardTitle>Create New Spark Cluster</CardTitle>
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
                  placeholder="my-spark-cluster"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
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

                <div>
                  <label className="block text-sm font-medium text-gray-900 mb-2">
                    Cores per Worker
                  </label>
                  <Input
                    type="number"
                    value={formData.coresPerWorker}
                    onChange={(e) => setFormData({ ...formData, coresPerWorker: parseInt(e.target.value) })}
                    min="1"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-900 mb-2">
                  Memory per Worker
                </label>
                <Input
                  type="text"
                  placeholder="4g"
                  value={formData.memoryPerWorker}
                  onChange={(e) => setFormData({ ...formData, memoryPerWorker: e.target.value })}
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

      {/* Clusters List */}
      <div className="space-y-4">
        {isLoading ? (
          <Card>
            <CardContent className="pt-6">
              <p className="text-gray-600">Loading clusters...</p>
            </CardContent>
          </Card>
        ) : !clusters || clusters.length === 0 ? (
          <Card>
            <CardContent className="pt-6">
              <p className="text-gray-600 text-center py-8">No Spark clusters found. Create one to get started.</p>
            </CardContent>
          </Card>
        ) : (
          clusters.map((cluster) => (
            <Card key={cluster.id}>
              <CardHeader className="flex flex-row items-start justify-between pb-3">
                <div>
                  <CardTitle>{cluster.name}</CardTitle>
                  <CardDescription>
                    Created {new Date(cluster.createdAt).toLocaleDateString()}
                  </CardDescription>
                </div>
                <div className={`flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(cluster.status)}`}>
                  {getStatusIcon(cluster.status)}
                  <span className="capitalize">{cluster.status}</span>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div>
                    <p className="text-xs text-gray-600">Master URL</p>
                    <p className="text-sm font-medium">{cluster.masterUrl}</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-600">Workers</p>
                    <p className="text-sm font-medium">{cluster.workers}</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-600">Memory/Worker</p>
                    <p className="text-sm font-medium">{cluster.memoryPerWorker}</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-600">Cores/Worker</p>
                    <p className="text-sm font-medium">{cluster.coresPerWorker}</p>
                  </div>
                </div>

                {showJobForm === cluster.id && (
                  <div className="border-t pt-4 mt-4">
                    <h4 className="font-medium text-sm mb-3">Submit Job</h4>
                    <form onSubmit={handleJobSubmit(cluster.id)} className="space-y-3">
                      <div>
                        <label className="block text-xs font-medium text-gray-900 mb-1">
                          JAR URL
                        </label>
                        <Input
                          type="text"
                          placeholder="s3://bucket/my-job.jar"
                          value={jobData.jarUrl}
                          onChange={(e) => setJobData({ ...jobData, jarUrl: e.target.value })}
                          required
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-gray-900 mb-1">
                          Main Class
                        </label>
                        <Input
                          type="text"
                          placeholder="com.example.Main"
                          value={jobData.mainClass}
                          onChange={(e) => setJobData({ ...jobData, mainClass: e.target.value })}
                          required
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-gray-900 mb-1">
                          Arguments (optional)
                        </label>
                        <Input
                          type="text"
                          placeholder="--key=value"
                          value={jobData.args}
                          onChange={(e) => setJobData({ ...jobData, args: e.target.value })}
                        />
                      </div>
                      <div className="flex gap-2">
                        <Button type="submit" size="sm" disabled={jobMutation.isPending}>
                          {jobMutation.isPending ? 'Submitting...' : 'Submit'}
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => setShowJobForm(null)}
                        >
                          Cancel
                        </Button>
                      </div>
                    </form>
                  </div>
                )}

                <div className="flex gap-2 mt-4">
                  {cluster.status === 'running' && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="gap-2"
                      onClick={() => setShowJobForm(cluster.id)}
                    >
                      <Play className="h-4 w-4" />
                      Submit Job
                    </Button>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-red-600 hover:text-red-700 gap-2"
                    onClick={() => deleteMutation.mutate(cluster.id)}
                    disabled={deleteMutation.isPending}
                  >
                    <Trash2 className="h-4 w-4" />
                    Delete
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
