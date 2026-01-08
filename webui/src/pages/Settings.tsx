import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/common/Card'
import { Button } from '@/components/common/Button'
import { Input } from '@/components/common/Input'
import { Alert, AlertDescription } from '@/components/common/Alert'
import { CheckCircle2, AlertCircle, Copy, RefreshCw, Eye, EyeOff } from 'lucide-react'

interface LicenseInfo {
  key: string
  status: 'valid' | 'invalid' | 'expired'
  expiresAt: string
  tier: 'free' | 'pro' | 'enterprise'
  features: string[]
}

interface MarchProxyStatus {
  running: boolean
  version: string
  uptime: number
  connections: number
}

async function fetchLicenseInfo(): Promise<LicenseInfo> {
  const response = await fetch('/api/settings/license')
  if (!response.ok) throw new Error('Failed to fetch license info')
  return response.json()
}

async function activateLicense(key: string): Promise<LicenseInfo> {
  const response = await fetch('/api/settings/license/activate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key }),
  })
  if (!response.ok) throw new Error('Failed to activate license')
  return response.json()
}

async function fetchMarchProxyStatus(): Promise<MarchProxyStatus> {
  const response = await fetch('/api/settings/proxy-status')
  if (!response.ok) throw new Error('Failed to fetch proxy status')
  return response.json()
}

function LicenseDisplay({ license }: { license: LicenseInfo }) {
  const [showKey, setShowKey] = useState(false)
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(license.key)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const statusConfig = {
    valid: { icon: CheckCircle2, color: 'text-green-600', bg: 'bg-green-50', label: 'Valid' },
    invalid: { icon: AlertCircle, color: 'text-red-600', bg: 'bg-red-50', label: 'Invalid' },
    expired: { icon: AlertCircle, color: 'text-yellow-600', bg: 'bg-yellow-50', label: 'Expired' },
  }
  const config = statusConfig[license.status]
  const StatusIcon = config.icon

  return (
    <Card className={config.bg}>
      <CardHeader>
        <div className="flex items-start justify-between">
          <div>
            <CardTitle>License Information</CardTitle>
            <CardDescription>{license.tier.toUpperCase()} Tier</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <StatusIcon className={`h-5 w-5 ${config.color}`} />
            <span className={`text-sm font-medium ${config.color}`}>{config.label}</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <p className="text-sm text-gray-600">License Key</p>
          <div className="flex gap-2 mt-2">
            <div className="flex-1 font-mono text-sm px-3 py-2 bg-gray-100 rounded-md">
              {showKey ? license.key : license.key.slice(0, 10) + '...'}
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowKey(!showKey)}
            >
              {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleCopy}
            >
              <Copy className="h-4 w-4" />
            </Button>
          </div>
          {copied && <p className="text-xs text-green-600 mt-1">Copied!</p>}
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-sm text-gray-600">Status</p>
            <p className="text-lg font-medium mt-1 capitalize">{license.status}</p>
          </div>
          <div>
            <p className="text-sm text-gray-600">Expires</p>
            <p className="text-lg font-medium mt-1">{new Date(license.expiresAt).toLocaleDateString()}</p>
          </div>
        </div>

        {license.features && license.features.length > 0 && (
          <div>
            <p className="text-sm text-gray-600 mb-2">Included Features</p>
            <ul className="space-y-1">
              {license.features.map((feature) => (
                <li key={feature} className="text-sm flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-600" />
                  {feature}
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function ActivateLicenseForm({ onSuccess }: { onSuccess: () => void }) {
  const [key, setKey] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError(null)
    try {
      await activateLicense(key)
      queryClient.invalidateQueries({ queryKey: ['license'] })
      setKey('')
      onSuccess()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to activate license')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {error && (
        <Alert variant="error">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div>
        <label className="text-sm font-medium">License Key</label>
        <Input
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="PENG-XXXX-XXXX-XXXX-XXXX"
          required
        />
      </div>
      <Button type="submit" className="w-full" disabled={isLoading}>
        {isLoading ? 'Activating...' : 'Activate License'}
      </Button>
    </form>
  )
}

function ProxyStatusDisplay({ status }: { status: MarchProxyStatus }) {
  const formatUptime = (seconds: number) => {
    const hours = Math.floor(seconds / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)
    return `${hours}h ${minutes}m`
  }

  return (
    <Card className={status.running ? 'bg-green-50' : 'bg-red-50'}>
      <CardHeader>
        <div className="flex items-start justify-between">
          <div>
            <CardTitle>MarchProxy Status</CardTitle>
            <CardDescription>Database proxy service</CardDescription>
          </div>
          {status.running ? (
            <CheckCircle2 className="h-5 w-5 text-green-600" />
          ) : (
            <AlertCircle className="h-5 w-5 text-red-600" />
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-sm text-gray-600">Status</p>
            <p className={`text-lg font-medium mt-1 ${status.running ? 'text-green-600' : 'text-red-600'}`}>
              {status.running ? 'Running' : 'Stopped'}
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-600">Version</p>
            <p className="text-lg font-medium mt-1">{status.version}</p>
          </div>
          <div>
            <p className="text-sm text-gray-600">Uptime</p>
            <p className="text-lg font-medium mt-1">{formatUptime(status.uptime)}</p>
          </div>
          <div>
            <p className="text-sm text-gray-600">Active Connections</p>
            <p className="text-lg font-medium mt-1">{status.connections}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

export default function Settings() {
  const [activateSuccess, setActivateSuccess] = useState(false)
  const queryClient = useQueryClient()

  const { data: license, isLoading: licenseLoading } = useQuery({
    queryKey: ['license'],
    queryFn: fetchLicenseInfo,
  })

  const { data: proxyStatus, isLoading: proxyLoading } = useQuery({
    queryKey: ['proxy-status'],
    queryFn: fetchMarchProxyStatus,
    refetchInterval: 30000,
  })

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-gray-600 mt-2">Manage your ArticDBM configuration and licensing</p>
      </div>

      {activateSuccess && (
        <Alert variant="success">
          <CheckCircle2 className="h-4 w-4" />
          <AlertDescription>License activated successfully!</AlertDescription>
        </Alert>
      )}

      {/* License Section */}
      <div className="space-y-4">
        <h2 className="text-xl font-semibold">Licensing</h2>
        {licenseLoading ? (
          <Card>
            <CardContent className="py-12 text-center">
              <RefreshCw className="h-8 w-8 animate-spin text-gray-400 mx-auto" />
            </CardContent>
          </Card>
        ) : license ? (
          <div className="grid gap-4 md:grid-cols-2">
            <LicenseDisplay license={license} />
            <Card>
              <CardHeader>
                <CardTitle>Change License</CardTitle>
                <CardDescription>Activate a new license key</CardDescription>
              </CardHeader>
              <CardContent>
                <ActivateLicenseForm onSuccess={() => setActivateSuccess(true)} />
              </CardContent>
            </Card>
          </div>
        ) : (
          <Card>
            <CardContent className="py-12 text-center">
              <AlertCircle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-600">Failed to load license information</p>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Proxy Status Section */}
      <div className="space-y-4">
        <h2 className="text-xl font-semibold">Service Status</h2>
        {proxyLoading ? (
          <Card>
            <CardContent className="py-12 text-center">
              <RefreshCw className="h-8 w-8 animate-spin text-gray-400 mx-auto" />
            </CardContent>
          </Card>
        ) : proxyStatus ? (
          <ProxyStatusDisplay status={proxyStatus} />
        ) : (
          <Card>
            <CardContent className="py-12 text-center">
              <AlertCircle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-600">Failed to load proxy status</p>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Additional Settings */}
      <div className="space-y-4">
        <h2 className="text-xl font-semibold">Additional Settings</h2>
        <Card>
          <CardHeader>
            <CardTitle>Account Preferences</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-sm font-medium">Default Timezone</label>
              <select className="w-full px-3 py-2 border rounded-md text-sm mt-1">
                <option>UTC</option>
                <option>EST</option>
                <option>PST</option>
                <option>CST</option>
              </select>
            </div>
            <div>
              <label className="text-sm font-medium">
                <input type="checkbox" className="mr-2" defaultChecked />
                Email notifications for critical alerts
              </label>
            </div>
            <Button variant="outline">Save Preferences</Button>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
