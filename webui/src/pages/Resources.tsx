import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/common/Card'
import { Button } from '@/components/common/Button'
import { Input } from '@/components/common/Input'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/common/Dialog'
import { Database, Plus, Search, CheckCircle2, AlertCircle, Loader } from 'lucide-react'

interface Resource {
  id: string
  name: string
  engine: 'postgres' | 'mysql' | 'sqlite' | 'mariadb'
  provider: string
  status: 'healthy' | 'unhealthy' | 'connecting'
  host: string
  port: number
  createdAt: string
}

interface ResourcesResponse {
  data: Resource[]
  total: number
  page: number
  pageSize: number
}

async function fetchResources(page: number, pageSize: number, search: string): Promise<ResourcesResponse> {
  const params = new URLSearchParams({
    page: String(page),
    pageSize: String(pageSize),
    search,
  })
  const response = await fetch(`/api/resources?${params}`)
  if (!response.ok) throw new Error('Failed to fetch resources')
  return response.json()
}

function ResourceCard({ resource }: { resource: Resource }) {
  const statusConfig = {
    healthy: { icon: CheckCircle2, color: 'text-green-600', bg: 'bg-green-50' },
    unhealthy: { icon: AlertCircle, color: 'text-red-600', bg: 'bg-red-50' },
    connecting: { icon: Loader, color: 'text-yellow-600', bg: 'bg-yellow-50' },
  }
  const config = statusConfig[resource.status]
  const StatusIcon = config.icon

  return (
    <Card className={config.bg}>
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div className="flex items-center gap-3">
          <Database className="h-5 w-5 text-muted-foreground" />
          <div>
            <CardTitle className="text-base">{resource.name}</CardTitle>
            <CardDescription>{resource.provider}</CardDescription>
          </div>
        </div>
        <StatusIcon className={`h-5 w-5 ${config.color}`} />
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-2 gap-2 text-sm">
          <div>
            <p className="text-gray-600">Engine</p>
            <p className="font-medium uppercase">{resource.engine}</p>
          </div>
          <div>
            <p className="text-gray-600">Host</p>
            <p className="font-medium text-sm truncate">{resource.host}</p>
          </div>
          <div>
            <p className="text-gray-600">Port</p>
            <p className="font-medium">{resource.port}</p>
          </div>
          <div>
            <p className="text-gray-600">Status</p>
            <p className="font-medium capitalize">{resource.status}</p>
          </div>
        </div>
        <p className="text-xs text-gray-500">Created {new Date(resource.createdAt).toLocaleDateString()}</p>
        <div className="flex gap-2 pt-2">
          <Button variant="outline" size="sm" className="flex-1">
            Test
          </Button>
          <Button variant="outline" size="sm" className="flex-1">
            Edit
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

export default function Resources() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const pageSize = 12

  const { data, isLoading } = useQuery({
    queryKey: ['resources', page, search],
    queryFn: () => fetchResources(page, pageSize, search),
  })

  const totalPages = data ? Math.ceil(data.total / pageSize) : 0

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold">Resources</h1>
          <p className="text-gray-600 mt-2">Manage your database connections</p>
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Create Resource
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create New Resource</DialogTitle>
              <DialogDescription>Add a new database connection to ArticDBM</DialogDescription>
            </DialogHeader>
            <CreateResourceForm onSuccess={() => setIsCreateOpen(false)} />
          </DialogContent>
        </Dialog>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
        <Input
          placeholder="Search resources by name..."
          className="pl-10"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value)
            setPage(1)
          }}
        />
      </div>

      {/* Resource Cards Grid */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader className="h-8 w-8 animate-spin text-gray-400" />
        </div>
      ) : data && data.data.length > 0 ? (
        <>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {data.data.map((resource) => (
              <ResourceCard key={resource.id} resource={resource} />
            ))}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2 pt-4">
              <Button
                variant="outline"
                onClick={() => setPage(Math.max(1, page - 1))}
                disabled={page === 1}
              >
                Previous
              </Button>
              <div className="px-3 py-1 border rounded-md text-sm">
                Page {page} of {totalPages}
              </div>
              <Button
                variant="outline"
                onClick={() => setPage(Math.min(totalPages, page + 1))}
                disabled={page === totalPages}
              >
                Next
              </Button>
            </div>
          )}
        </>
      ) : (
        <Card className="text-center py-12">
          <CardContent>
            <Database className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium">No resources found</h3>
            <p className="text-gray-600 mt-2">Create your first resource to get started</p>
            <Button className="mt-4" onClick={() => setIsCreateOpen(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Create Resource
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function CreateResourceForm({ onSuccess }: { onSuccess: () => void }) {
  const [formData, setFormData] = useState({
    name: '',
    engine: 'postgres' as const,
    provider: '',
    host: '',
    port: '5432',
    username: '',
    password: '',
  })
  const [isLoading, setIsLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    try {
      const response = await fetch('/api/resources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      })
      if (response.ok) {
        onSuccess()
      }
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="text-sm font-medium">Name</label>
        <Input
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          placeholder="My Database"
          required
        />
      </div>
      <div>
        <label className="text-sm font-medium">Engine</label>
        <select
          value={formData.engine}
          onChange={(e) => setFormData({ ...formData, engine: e.target.value as any })}
          className="w-full px-3 py-2 border rounded-md text-sm"
        >
          <option value="postgres">PostgreSQL</option>
          <option value="mysql">MySQL</option>
          <option value="mariadb">MariaDB</option>
          <option value="sqlite">SQLite</option>
        </select>
      </div>
      <div>
        <label className="text-sm font-medium">Host</label>
        <Input
          value={formData.host}
          onChange={(e) => setFormData({ ...formData, host: e.target.value })}
          placeholder="localhost"
          required
        />
      </div>
      <div>
        <label className="text-sm font-medium">Port</label>
        <Input
          value={formData.port}
          onChange={(e) => setFormData({ ...formData, port: e.target.value })}
          type="number"
          required
        />
      </div>
      <Button type="submit" className="w-full" disabled={isLoading}>
        {isLoading ? 'Creating...' : 'Create Resource'}
      </Button>
    </form>
  )
}
