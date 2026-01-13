import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/common/Card'
import { Alert, AlertDescription } from '@/components/common/Alert'
import { Activity, Database, AlertCircle, CheckCircle2, Zap, Filter } from 'lucide-react'
import { apiClient } from '@/services/api'

interface LicenseData {
  tier: string
  resource_limit: number
  resource_count: number
}

interface ResourcesData {
  resources: any[]
  total: number
  page: number
  page_size: number
}

interface ApplicationsData {
  applications: any[]
  total: number
  page: number
  page_size: number
}

interface ClustersData {
  clusters: any[]
  total: number
  page: number
  page_size: number
}

async function fetchLicense(): Promise<LicenseData> {
  const response = await apiClient.get<LicenseData>('/license')
  return response.data
}

async function fetchResources(): Promise<ResourcesData> {
  const response = await apiClient.get<ResourcesData>('/resources')
  return response.data
}

async function fetchApplications(): Promise<ApplicationsData> {
  const response = await apiClient.get<ApplicationsData>('/applications')
  return response.data
}

async function fetchClusters(type: 'spark' | 'flink' | 'trino' | 'hdfs'): Promise<ClustersData> {
  const response = await apiClient.get<ClustersData>(`/${type}`)
  return response.data
}

export default function Dashboard() {
  const { data: license, isLoading: licenseLoading } = useQuery({
    queryKey: ['license'],
    queryFn: fetchLicense,
    refetchInterval: 30000,
  })

  const { data: resources, isLoading: resourcesLoading } = useQuery({
    queryKey: ['resources'],
    queryFn: fetchResources,
    refetchInterval: 30000,
  })

  const { data: applications, isLoading: applicationsLoading } = useQuery({
    queryKey: ['applications'],
    queryFn: fetchApplications,
    refetchInterval: 30000,
  })

  const { data: sparkClusters } = useQuery({
    queryKey: ['spark'],
    queryFn: () => fetchClusters('spark'),
    refetchInterval: 30000,
  })

  const { data: flinkClusters } = useQuery({
    queryKey: ['flink'],
    queryFn: () => fetchClusters('flink'),
    refetchInterval: 30000,
  })

  const { data: trinoClusters } = useQuery({
    queryKey: ['trino'],
    queryFn: () => fetchClusters('trino'),
    refetchInterval: 30000,
  })

  const { data: hdfsClusters } = useQuery({
    queryKey: ['hdfs'],
    queryFn: () => fetchClusters('hdfs'),
    refetchInterval: 30000,
  })

  const resourceUsagePercent = license ? (license.resource_count / license.resource_limit) * 100 : 0
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

      {/* Stats Cards - Databases & Cache */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Resources</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{resourcesLoading ? '-' : resources?.total}</div>
            <p className="text-xs text-gray-600">Database connections</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Applications</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{applicationsLoading ? '-' : applications?.total}</div>
            <p className="text-xs text-gray-600">Connected applications</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">License Tier</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{licenseLoading ? '-' : license?.tier}</div>
            <p className="text-xs text-gray-600">Current plan</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Uptime</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">99.9%</div>
            <p className="text-xs text-gray-600">System availability</p>
          </CardContent>
        </Card>
      </div>

      {/* Resource Limit Indicator */}
      <Card>
        <CardHeader>
          <CardTitle>Resource Limit</CardTitle>
          <CardDescription>{license?.tier} tier: {license?.resource_limit} resources</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>Used: {license?.resource_count || 0}</span>
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
              {license?.resource_limit && license.resource_count ? `${license.resource_limit - license.resource_count} remaining` : ''}
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Big Data Clusters Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5" />
            Big Data Clusters
          </CardTitle>
          <CardDescription>Summary of deployed cluster management systems</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <div className="border rounded-lg p-4">
              <h4 className="font-semibold text-sm mb-2">Spark Clusters</h4>
              <p className="text-3xl font-bold">{sparkClusters?.total || 0}</p>
              <p className="text-xs text-gray-600 mt-1">Total clusters</p>
            </div>
            <div className="border rounded-lg p-4">
              <h4 className="font-semibold text-sm mb-2">Flink Clusters</h4>
              <p className="text-3xl font-bold">{flinkClusters?.total || 0}</p>
              <p className="text-xs text-gray-600 mt-1">Total clusters</p>
            </div>
            <div className="border rounded-lg p-4">
              <h4 className="font-semibold text-sm mb-2">Trino Clusters</h4>
              <p className="text-3xl font-bold">{trinoClusters?.total || 0}</p>
              <p className="text-xs text-gray-600 mt-1">Total clusters</p>
            </div>
            <div className="border rounded-lg p-4">
              <h4 className="font-semibold text-sm mb-2">HDFS Clusters</h4>
              <p className="text-3xl font-bold">{hdfsClusters?.total || 0}</p>
              <p className="text-xs text-gray-600 mt-1">Total clusters</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Quick Links */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Filter className="h-5 w-5" />
            Quick Navigation
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-2 md:grid-cols-3">
            <a href="/resources" className="p-3 border rounded-lg hover:bg-gray-50 transition">
              <p className="font-medium text-sm">View Resources</p>
              <p className="text-xs text-gray-600">Manage databases and cache</p>
            </a>
            <a href="/applications" className="p-3 border rounded-lg hover:bg-gray-50 transition">
              <p className="font-medium text-sm">Applications</p>
              <p className="text-xs text-gray-600">Connected applications</p>
            </a>
            <a href="/providers" className="p-3 border rounded-lg hover:bg-gray-50 transition">
              <p className="font-medium text-sm">Big Data</p>
              <p className="text-xs text-gray-600">Spark, Flink, Trino, HDFS</p>
            </a>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
