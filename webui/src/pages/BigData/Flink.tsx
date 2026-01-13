import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/common/Card';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { Alert, AlertDescription } from '@/components/common/Alert';
import { AlertCircle, CheckCircle2, Play, Square, Trash2, Plus, Save } from 'lucide-react';
import { apiClient } from '@/services/api';

interface FlinkCluster {
  id: string;
  name: string;
  status: 'running' | 'stopped' | 'error';
  jobManagerUrl: string;
  taskManagers: number;
  slotsPerTaskManager: number;
  createdAt: string;
  jobs: {
    id: string;
    name: string;
    status: 'running' | 'finished' | 'failed' | 'cancelled';
  }[];
}

async function fetchFlinkClusters(): Promise<FlinkCluster[]> {
  const response = await apiClient.get<{ data: FlinkCluster[] }>('/flink');
  return response.data?.data || [];
}

async function createFlinkCluster(data: any): Promise<FlinkCluster> {
  const response = await apiClient.post<{ data: FlinkCluster }>('/flink', data);
  return response.data?.data || data;
}

async function submitFlinkJob(clusterId: string, jobData: any): Promise<any> {
  const response = await apiClient.post(`/flink/${clusterId}/jobs`, jobData);
  return response.data;
}

async function createSavepoint(clusterId: string, jobId: string): Promise<any> {
  const response = await apiClient.post(`/flink/${clusterId}/jobs/${jobId}/savepoint`);
  return response.data;
}

async function deleteFlinkCluster(clusterId: string): Promise<void> {
  await apiClient.delete(`/flink/${clusterId}`);
}

export default function FlinkPage() {
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [showJobForm, setShowJobForm] = useState<string | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    taskManagers: '3',
    slotsPerTaskManager: '4',
  });
  const [jobData, setJobData] = useState({
    jarUrl: '',
    mainClass: '',
    args: '',
  });
  const [error, setError] = useState<string | null>(null);

  const queryClient = useQueryClient();

  const { data: clusters, isLoading } = useQuery({
    queryKey: ['flink', 'clusters'],
    queryFn: fetchFlinkClusters,
    refetchInterval: 30000,
  });

  const createMutation = useMutation({
    mutationFn: (data) => createFlinkCluster(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['flink', 'clusters'] });
      setShowCreateForm(false);
      setFormData({ name: '', taskManagers: '3', slotsPerTaskManager: '4' });
      setError(null);
    },
    onError: (err: any) => {
      setError(err.message || 'Failed to create cluster');
    },
  });

  const jobMutation = useMutation({
    mutationFn: (data: any) => submitFlinkJob(data.clusterId, data.job),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['flink', 'clusters'] });
      setShowJobForm(null);
      setJobData({ jarUrl: '', mainClass: '', args: '' });
      setError(null);
    },
    onError: (err: any) => {
      setError(err.message || 'Failed to submit job');
    },
  });

  const savepointMutation = useMutation({
    mutationFn: (data: any) => createSavepoint(data.clusterId, data.jobId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['flink', 'clusters'] });
      setError(null);
    },
    onError: (err: any) => {
      setError(err.message || 'Failed to create savepoint');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (clusterId: string) => deleteFlinkCluster(clusterId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['flink', 'clusters'] });
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
      case 'finished':
        return 'text-blue-600 bg-blue-50';
      case 'failed':
        return 'text-red-600 bg-red-50';
      case 'cancelled':
        return 'text-gray-600 bg-gray-50';
      default:
        return 'text-gray-600 bg-gray-50';
    }
  };

  const getStatusIcon = (status: string) => {
    if (status === 'running') return <CheckCircle2 className="h-4 w-4" />;
    if (status === 'error' || status === 'failed') return <AlertCircle className="h-4 w-4" />;
    return <Square className="h-4 w-4" />;
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold">Flink Clusters</h1>
          <p className="text-gray-600 mt-2">Manage stream processing with Apache Flink</p>
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
            <CardTitle>Create New Flink Cluster</CardTitle>
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
                  placeholder="my-flink-cluster"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-900 mb-2">
                    Task Managers
                  </label>
                  <Input
                    type="number"
                    value={formData.taskManagers}
                    onChange={(e) => setFormData({ ...formData, taskManagers: e.target.value })}
                    min="1"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-900 mb-2">
                    Slots per Task Manager
                  </label>
                  <Input
                    type="number"
                    value={formData.slotsPerTaskManager}
                    onChange={(e) => setFormData({ ...formData, slotsPerTaskManager: e.target.value })}
                    min="1"
                    required
                  />
                </div>
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
              <p className="text-gray-600 text-center py-8">No Flink clusters found. Create one to get started.</p>
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
                    <p className="text-xs text-gray-600">JobManager URL</p>
                    <p className="text-sm font-medium">{cluster.jobManagerUrl}</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-600">Task Managers</p>
                    <p className="text-sm font-medium">{cluster.taskManagers}</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-600">Slots/TM</p>
                    <p className="text-sm font-medium">{cluster.slotsPerTaskManager}</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-600">Total Slots</p>
                    <p className="text-sm font-medium">{cluster.taskManagers * cluster.slotsPerTaskManager}</p>
                  </div>
                </div>

                {/* Running Jobs */}
                {cluster.jobs && cluster.jobs.length > 0 && (
                  <div className="border-t pt-4 mt-4">
                    <h4 className="font-medium text-sm mb-3">Running Jobs ({cluster.jobs.length})</h4>
                    <div className="space-y-2 mb-4">
                      {cluster.jobs.map((job) => (
                        <div
                          key={job.id}
                          className="flex items-center justify-between p-2 bg-gray-50 rounded"
                        >
                          <div>
                            <p className="text-sm font-medium">{job.name}</p>
                            <p className="text-xs text-gray-600">{job.id}</p>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(job.status)}`}>
                              {job.status}
                            </span>
                            {job.status === 'running' && (
                              <Button
                                variant="outline"
                                size="sm"
                                className="gap-1"
                                onClick={() => savepointMutation.mutate({ clusterId: cluster.id, jobId: job.id })}
                                disabled={savepointMutation.isPending}
                              >
                                <Save className="h-3 w-3" />
                                Savepoint
                              </Button>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Submit Job Form */}
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
                          placeholder="com.example.StreamJob"
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
                          placeholder="--parallelism=4"
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
