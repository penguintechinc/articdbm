import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/common/Card';
import { Button } from '@/components/common/Button';
import { Alert, AlertDescription } from '@/components/common/Alert';
import { Zap, Database, AlertCircle, ArrowRight } from 'lucide-react';
import { apiClient } from '@/services/api';

interface BigDataStats {
  sparkCount: number;
  flinkCount: number;
  trinoCount: number;
  storageCount: number;
}

async function fetchBigDataStats(): Promise<BigDataStats> {
  try {
    const [sparkRes, flinkRes, trinoRes, storageRes] = await Promise.all([
      apiClient.get('/spark').catch(() => ({ data: { data: [] } })),
      apiClient.get('/flink').catch(() => ({ data: { data: [] } })),
      apiClient.get('/trino').catch(() => ({ data: { data: [] } })),
      apiClient.get('/storage').catch(() => ({ data: { data: [] } })),
    ]);

    return {
      sparkCount: sparkRes.data?.data?.length || 0,
      flinkCount: flinkRes.data?.data?.length || 0,
      trinoCount: trinoRes.data?.data?.length || 0,
      storageCount: storageRes.data?.data?.length || 0,
    };
  } catch (error) {
    return {
      sparkCount: 0,
      flinkCount: 0,
      trinoCount: 0,
      storageCount: 0,
    };
  }
}

export default function BigDataDashboard() {
  const navigate = useNavigate();
  const { data: stats, isLoading } = useQuery({
    queryKey: ['bigdata', 'stats'],
    queryFn: fetchBigDataStats,
    refetchInterval: 60000,
  });

  const quickLinks = [
    {
      title: 'Spark Clusters',
      count: stats?.sparkCount || 0,
      description: 'Manage Apache Spark clusters',
      path: '/bigdata/spark',
      icon: Zap,
      color: 'text-orange-600',
    },
    {
      title: 'Flink Jobs',
      count: stats?.flinkCount || 0,
      description: 'Stream processing with Apache Flink',
      path: '/bigdata/flink',
      icon: Zap,
      color: 'text-blue-600',
    },
    {
      title: 'Trino Clusters',
      count: stats?.trinoCount || 0,
      description: 'SQL query engine for analytics',
      path: '/bigdata/trino',
      icon: Database,
      color: 'text-purple-600',
    },
    {
      title: 'Storage Backends',
      count: stats?.storageCount || 0,
      description: 'S3, GCS, Azure, MinIO storage',
      path: '/bigdata/storage',
      icon: Database,
      color: 'text-green-600',
    },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">Big Data Management</h1>
        <p className="text-gray-600 mt-2">
          Manage and monitor your Spark, Flink, Trino, and storage infrastructure
        </p>
      </div>

      {/* Stats Overview */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {quickLinks.map((link) => {
          const Icon = link.icon;
          return (
            <Card key={link.path} className="hover:shadow-md transition-shadow">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">{link.title}</CardTitle>
                <Icon className={`h-4 w-4 ${link.color}`} />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {isLoading ? '-' : link.count}
                </div>
                <p className="text-xs text-gray-600 mt-2">{link.description}</p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Quick Navigation */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Access</CardTitle>
          <CardDescription>Navigate to specific Big Data components</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {quickLinks.map((link) => (
              <button
                key={link.path}
                onClick={() => navigate(link.path)}
                className="p-4 rounded-lg border border-gray-200 hover:border-blue-400 hover:bg-blue-50 transition-all text-left group"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="font-medium text-gray-900 group-hover:text-blue-600">
                      {link.title}
                    </h3>
                    <p className="text-xs text-gray-600 mt-1">{link.description}</p>
                  </div>
                  <ArrowRight className="h-4 w-4 text-gray-400 group-hover:text-blue-600 mt-1" />
                </div>
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Getting Started */}
      <Card>
        <CardHeader>
          <CardTitle>Getting Started</CardTitle>
          <CardDescription>New to Big Data management?</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <p className="text-sm text-gray-700">
              ArticDBM provides unified management for your big data infrastructure:
            </p>
            <ul className="space-y-2 text-sm text-gray-600">
              <li className="flex items-start">
                <span className="text-blue-600 mr-2">•</span>
                <span><strong>Spark:</strong> Create and manage distributed computing clusters</span>
              </li>
              <li className="flex items-start">
                <span className="text-blue-600 mr-2">•</span>
                <span><strong>Flink:</strong> Stream processing with stateful computations</span>
              </li>
              <li className="flex items-start">
                <span className="text-blue-600 mr-2">•</span>
                <span><strong>Trino:</strong> Fast SQL queries across data sources</span>
              </li>
              <li className="flex items-start">
                <span className="text-blue-600 mr-2">•</span>
                <span><strong>Storage:</strong> Connect and manage cloud storage backends</span>
              </li>
            </ul>
            <div className="pt-4">
              <Button
                onClick={() => navigate('/bigdata/spark')}
                className="w-full"
              >
                Create Your First Spark Cluster
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
