import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/common/Card'
import { Alert, AlertDescription } from '@/components/common/Alert'
import { Activity, Database, AlertCircle, CheckCircle2 } from 'lucide-react'

interface DashboardStats {
  totalResources: number
  healthyResources: number
  unhealthyResources: number
  totalApplications: number
  resourceLimit: number
  usedResources: number
}

interface ActivityLog {
  id: string
  type: 'create' | 'update' | 'delete' | 'connect'
  resource: string
  timestamp: string
  status: 'success' | 'error'
}

async function fetchDashboardStats(): Promise<DashboardStats> {
  const response = await fetch('/api/dashboard/stats')
  if (!response.ok) throw new Error('Failed to fetch stats')
  return response.json()
}

async function fetchRecentActivity(): Promise<ActivityLog[]> {
  const response = await fetch('/api/dashboard/activity?limit=10')
  if (!response.ok) throw new Error('Failed to fetch activity')
  return response.json()
}

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: fetchDashboardStats,
    refetchInterval: 30000,
  })

  const { data: activity, isLoading: activityLoading } = useQuery({
    queryKey: ['dashboard', 'activity'],
    queryFn: fetchRecentActivity,
    refetchInterval: 30000,
  })

  const resourceUsagePercent = stats ? (stats.usedResources / stats.resourceLimit) * 100 : 0
  const isNearLimit = resourceUsagePercent > 80

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-gray-600 mt-2">Overview of your ArticDBM resources and activity</p>
      </div>

      {/* Resource Limit Alert */}
      {isNearLimit && (
        <Alert variant="warning">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            You are using {resourceUsagePercent.toFixed(1)}% of your resource limit. Consider upgrading your plan.
          </AlertDescription>
        </Alert>
      )}

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Resources</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statsLoading ? '-' : stats?.totalResources}</div>
            <p className="text-xs text-gray-600">Database connections</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Healthy Resources</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statsLoading ? '-' : stats?.healthyResources}</div>
            <p className="text-xs text-gray-600">Operating normally</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Unhealthy Resources</CardTitle>
            <AlertCircle className="h-4 w-4 text-red-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statsLoading ? '-' : stats?.unhealthyResources}</div>
            <p className="text-xs text-gray-600">Require attention</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Applications</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statsLoading ? '-' : stats?.totalApplications}</div>
            <p className="text-xs text-gray-600">Connected applications</p>
          </CardContent>
        </Card>
      </div>

      {/* Resource Limit Indicator */}
      <Card>
        <CardHeader>
          <CardTitle>Resource Limit</CardTitle>
          <CardDescription>Free tier: {stats?.resourceLimit} resources</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>Used: {stats?.usedResources || 0}</span>
              <span className={isNearLimit ? 'text-red-600' : 'text-green-600'}>
                {resourceUsagePercent.toFixed(1)}%
              </span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className={`h-2 rounded-full transition-all ${isNearLimit ? 'bg-red-600' : 'bg-green-600'}`}
                style={{ width: `${Math.min(resourceUsagePercent, 100)}%` }}
              ></div>
            </div>
            <p className="text-xs text-gray-600">
              {stats?.resourceLimit && stats.usedResources ? `${stats.resourceLimit - stats.usedResources} remaining` : ''}
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Recent Activity */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Activity</CardTitle>
          <CardDescription>Latest operations on your resources</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {activityLoading ? (
              <p className="text-sm text-gray-600">Loading activity...</p>
            ) : activity && activity.length > 0 ? (
              activity.map((item) => (
                <div key={item.id} className="flex items-start justify-between border-b pb-4 last:border-b-0">
                  <div className="space-y-1">
                    <p className="text-sm font-medium capitalize">{item.type}</p>
                    <p className="text-sm text-gray-600">{item.resource}</p>
                    <p className="text-xs text-gray-500">{new Date(item.timestamp).toLocaleString()}</p>
                  </div>
                  <div className={`px-3 py-1 rounded-full text-xs font-medium ${
                    item.status === 'success' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                  }`}>
                    {item.status}
                  </div>
                </div>
              ))
            ) : (
              <p className="text-sm text-gray-600">No recent activity</p>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
