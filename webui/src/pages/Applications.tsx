import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/common/Card'
import { Button } from '@/components/common/Button'
import { Input } from '@/components/common/Input'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/common/Dialog'
import { AlertCircle, Plus, Trash2, RefreshCw } from 'lucide-react'

interface Application {
  id: string
  name: string
  type: 'web' | 'mobile' | 'cli' | 'service'
  status: 'active' | 'inactive'
  lastSync: string
  createdAt: string
}

interface ApplicationsResponse {
  data: Application[]
  total: number
}

async function fetchApplications(): Promise<ApplicationsResponse> {
  const response = await fetch('/api/applications')
  if (!response.ok) throw new Error('Failed to fetch applications')
  return response.json()
}

async function createApplication(data: any): Promise<Application> {
  const response = await fetch('/api/applications', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!response.ok) throw new Error('Failed to create application')
  return response.json()
}

async function syncApplications(): Promise<void> {
  const response = await fetch('/api/applications/sync', {
    method: 'POST',
  })
  if (!response.ok) throw new Error('Failed to sync applications')
}

async function deleteApplication(id: string): Promise<void> {
  const response = await fetch(`/api/applications/${id}`, {
    method: 'DELETE',
  })
  if (!response.ok) throw new Error('Failed to delete application')
}

function ApplicationRow({ app, onDelete }: { app: Application; onDelete: (id: string) => void }) {
  const statusColor = app.status === 'active' ? 'text-green-600 bg-green-50' : 'text-gray-600 bg-gray-50'

  return (
    <div className={`flex items-center justify-between p-4 border rounded-lg ${statusColor}`}>
      <div className="flex-1">
        <p className="font-medium">{app.name}</p>
        <div className="flex gap-4 mt-1 text-sm text-gray-600">
          <span>Type: {app.type.toUpperCase()}</span>
          <span>Status: {app.status}</span>
          <span>Last Sync: {new Date(app.lastSync).toLocaleDateString()}</span>
        </div>
      </div>
      <div className="flex gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => onDelete(app.id)}
          className="text-red-600 hover:bg-red-50"
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>
    </div>
  )
}

export default function Applications() {
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['applications'],
    queryFn: fetchApplications,
    refetchInterval: 30000,
  })

  const createMutation = useMutation({
    mutationFn: createApplication,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['applications'] })
      setIsCreateOpen(false)
    },
  })

  const syncMutation = useMutation({
    mutationFn: syncApplications,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['applications'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: deleteApplication,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['applications'] })
    },
  })

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold">Applications</h1>
          <p className="text-gray-600 mt-2">Manage applications connected to ArticDBM</p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => syncMutation.mutate()}
            disabled={syncMutation.isPending}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
            Elder Sync
          </Button>
          <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                Create Application
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create New Application</DialogTitle>
                <DialogDescription>Register a new application with ArticDBM</DialogDescription>
              </DialogHeader>
              <CreateApplicationForm onSuccess={() => setIsCreateOpen(false)} onSubmit={createMutation.mutate} />
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Applications List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="h-8 w-8 animate-spin text-gray-400" />
        </div>
      ) : data && data.data.length > 0 ? (
        <div className="space-y-3">
          {data.data.map((app) => (
            <ApplicationRow
              key={app.id}
              app={app}
              onDelete={(id) => deleteMutation.mutate(id)}
            />
          ))}
        </div>
      ) : (
        <Card className="text-center py-12">
          <CardContent>
            <AlertCircle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium">No applications found</h3>
            <p className="text-gray-600 mt-2">Create your first application to connect to ArticDBM</p>
            <Button className="mt-4" onClick={() => setIsCreateOpen(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Create Application
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Summary */}
      {data && data.total > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-gray-600">Total Applications</p>
                <p className="text-2xl font-bold">{data.total}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600">Active</p>
                <p className="text-2xl font-bold text-green-600">
                  {data.data.filter((a) => a.status === 'active').length}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function CreateApplicationForm({
  onSuccess,
  onSubmit,
}: {
  onSuccess: () => void
  onSubmit: (data: any) => void
}) {
  const [formData, setFormData] = useState({
    name: '',
    type: 'web' as const,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(formData)
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="text-sm font-medium">Application Name</label>
        <Input
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          placeholder="My App"
          required
        />
      </div>
      <div>
        <label className="text-sm font-medium">Type</label>
        <select
          value={formData.type}
          onChange={(e) => setFormData({ ...formData, type: e.target.value as any })}
          className="w-full px-3 py-2 border rounded-md text-sm"
        >
          <option value="web">Web Application</option>
          <option value="mobile">Mobile Application</option>
          <option value="cli">CLI Tool</option>
          <option value="service">Background Service</option>
        </select>
      </div>
      <Button type="submit" className="w-full">
        Create Application
      </Button>
    </form>
  )
}
