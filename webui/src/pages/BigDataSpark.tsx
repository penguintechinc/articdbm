import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/common/Card';
import { Button } from '@/components/common/Button';
import { Zap, Play, Square, Activity } from 'lucide-react';

export default function BigDataSpark() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold flex items-center space-x-3">
          <Zap className="h-8 w-8 text-orange-600" />
          <span>Apache Spark</span>
        </h1>
        <p className="text-gray-600 mt-2">Unified analytics engine for large-scale data processing</p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Cluster Status</CardTitle>
            <CardDescription>Current Spark cluster state</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">Status:</span>
                <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm">Running</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">Workers:</span>
                <span className="text-sm">4</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">Active Jobs:</span>
                <span className="text-sm">2</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
            <CardDescription>Manage your Spark cluster</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button className="w-full" variant="default">
              <Play className="h-4 w-4 mr-2" />
              Submit Job
            </Button>
            <Button className="w-full" variant="outline">
              <Activity className="h-4 w-4 mr-2" />
              View Metrics
            </Button>
            <Button className="w-full" variant="outline">
              <Square className="h-4 w-4 mr-2" />
              Stop Cluster
            </Button>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent Jobs</CardTitle>
          <CardDescription>Latest Spark job executions</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-gray-600">No recent jobs</p>
        </CardContent>
      </Card>
    </div>
  );
}
