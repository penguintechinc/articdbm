import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/common/Card'
import { Button } from '@/components/common/Button'
import { Input } from '@/components/common/Input'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/common/Dialog'
import { AlertCircle, Plus, CheckCircle2, XCircle, RefreshCw } from 'lucide-react'

interface Provider {
  id: string
  name: string
  type: 'postgres' | 'mysql' | 'mariadb' | 'sqlite' | 'custom'
  host: string
  port: number
  status: 'connected' | 'disconnected' | 'testing'
  createdAt: string
}

interface ProvidersResponse {
  data: Provider[]
  total: number
}

async function fetchProviders(): Promise<ProvidersResponse> {
  const response = await fetch('/api/providers')
  if (!response.ok) throw new Error('Failed to fetch providers')
  return response.json()
}

async function createProvider(data: any): Promise<Provider> {
  const response = await fetch('/api/providers', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!response.ok) throw new Error('Failed to create provider')
  return response.json()
}

async function testProviderConnection(id: string): Promise<{ success: boolean; message: string }> {
  const response = await fetch(`/api/providers/${id}/test`, {
    method: 'POST',
  })
  if (!response.ok) throw new Error('Failed to test connection')
  return response.json()
}

function ProviderCard({ provider }: { provider: Provider }) {
  const [isTesting, setIsTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const queryClient = useQueryClient()

  const handleTest = async () => {
    setIsTesting(true)
    try {
      const result = await testProviderConnection(provider.id)
      setTestResult(result)
      queryClient.invalidateQueries({ queryKey: ['providers'] })
    } finally {
      setIsTesting(false)
    }
  }

  const statusConfig = {
    connected: { icon: CheckCircle2, color: 'text-green-600', bg: 'bg-green-50' },
    disconnected: { icon: XCircle, color: 'text-red-600', bg: 'bg-red-50' },
    testing: { icon: RefreshCw, color: 'text-yellow-600', bg: 'bg-yellow-50' },
  }
  const config = statusConfig[provider.status]
  const StatusIcon = config.icon

  return (
    <Card className={config.bg}>
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle>{provider.name}</CardTitle>
          <CardDescription>{provider.type.toUpperCase()}</CardDescription>
        </div>
        <StatusIcon className={`h-5 w-5 ${config.color}`} />
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-2 gap-2 text-sm">
          <div>
            <p className="text-gray-600">Host</p>
            <p className="font-medium text-sm truncate">{provider.host}</p>
          </div>
          <div>
            <p className="text-gray-600">Port</p>
            <p className="font-medium">{provider.port}</p>
          </div>
        </div>
        <div className="flex flex-col gap-2">
          <p className="text-xs text-gray-500">Status: {provider.status}</p>
          {testResult && (
            <div className={`text-xs px-2 py-1 rounded ${testResult.success ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
              {testResult.message}
            </div>
          )}
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={handleTest}
          disabled={isTesting}
          className="w-full"
        >
          {isTesting ? 'Testing...' : 'Test Connection'}
        </Button>
      </CardContent>
    </Card>
  )
}

export default function Providers() {
  const [isAddOpen, setIsAddOpen] = useState(false)
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['providers'],
    queryFn: fetchProviders,
    refetchInterval: 30000,
  })

  const createMutation = useMutation({
    mutationFn: createProvider,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['providers'] })
      setIsAddOpen(false)
    },
  })

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold">Providers</h1>
          <p className="text-gray-600 mt-2">Configure database providers</p>
        </div>
        <Dialog open={isAddOpen} onOpenChange={setIsAddOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Add Provider
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add Provider</DialogTitle>
              <DialogDescription>Configure a new database provider connection</DialogDescription>
            </DialogHeader>
            <AddProviderForm
              onSuccess={() => setIsAddOpen(false)}
              onSubmit={createMutation.mutate}
            />
          </DialogContent>
        </Dialog>
      </div>

      {/* Provider Cards Grid */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="h-8 w-8 animate-spin text-gray-400" />
        </div>
      ) : data && data.data.length > 0 ? (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {data.data.map((provider) => (
            <ProviderCard key={provider.id} provider={provider} />
          ))}
        </div>
      ) : (
        <Card className="text-center py-12">
          <CardContent>
            <AlertCircle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium">No providers configured</h3>
            <p className="text-gray-600 mt-2">Add your first database provider to get started</p>
            <Button className="mt-4" onClick={() => setIsAddOpen(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Add Provider
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
            <div className="grid grid-cols-3 gap-4">
              <div>
                <p className="text-sm text-gray-600">Total Providers</p>
                <p className="text-2xl font-bold">{data.total}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600">Connected</p>
                <p className="text-2xl font-bold text-green-600">
                  {data.data.filter((p) => p.status === 'connected').length}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-600">Disconnected</p>
                <p className="text-2xl font-bold text-red-600">
                  {data.data.filter((p) => p.status === 'disconnected').length}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function AddProviderForm({
  onSuccess,
  onSubmit,
}: {
  onSuccess: () => void
  onSubmit: (data: any) => void
}) {
  const [formData, setFormData] = useState({
    name: '',
    type: 'postgres' as const,
    host: 'localhost',
    port: '5432',
    username: '',
    password: '',
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit({
      ...formData,
      port: parseInt(formData.port),
    })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="text-sm font-medium">Provider Name</label>
        <Input
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          placeholder="Production DB"
          required
        />
      </div>
      <div>
        <label className="text-sm font-medium">Database Type</label>
        <select
          value={formData.type}
          onChange={(e) => setFormData({ ...formData, type: e.target.value as any })}
          className="w-full px-3 py-2 border rounded-md text-sm"
        >
          <option value="postgres">PostgreSQL</option>
          <option value="mysql">MySQL</option>
          <option value="mariadb">MariaDB</option>
          <option value="sqlite">SQLite</option>
          <option value="custom">Custom</option>
        </select>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="text-sm font-medium">Host</label>
          <Input
            value={formData.host}
            onChange={(e) => setFormData({ ...formData, host: e.target.value })}
            required
          />
        </div>
        <div>
          <label className="text-sm font-medium">Port</label>
          <Input
            type="number"
            value={formData.port}
            onChange={(e) => setFormData({ ...formData, port: e.target.value })}
            required
          />
        </div>
      </div>
      <div>
        <label className="text-sm font-medium">Username (optional)</label>
        <Input
          value={formData.username}
          onChange={(e) => setFormData({ ...formData, username: e.target.value })}
        />
      </div>
      <div>
        <label className="text-sm font-medium">Password (optional)</label>
        <Input
          type="password"
          value={formData.password}
          onChange={(e) => setFormData({ ...formData, password: e.target.value })}
        />
      </div>
      <Button type="submit" className="w-full">
        Add Provider
      </Button>
    </form>
  )
}
