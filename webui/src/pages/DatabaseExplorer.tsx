import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/common/Card'
import { Button } from '@/components/common/Button'
import { Input } from '@/components/common/Input'
import { Database, AlertTriangle, ChevronLeft, ChevronRight } from 'lucide-react'
import { apiClient } from '@/services/api'

interface Cluster {
  id: number
  name: string
  description?: string
  provider_id: number
}

interface Database {
  name: string
}

interface Column {
  name: string
  type: string
  pii: boolean
  pii_type?: string
  masked?: boolean
}

interface Row {
  [key: string]: any
}

interface QueryResult {
  table: string
  total_rows: number
  page: number
  per_page: number
  columns: Column[]
  rows: Row[]
  pii_detected: boolean
  pii_access_granted: boolean
  audit_logged: boolean
}

export default function DatabaseExplorer() {
  const [selectedCluster, setSelectedCluster] = useState<number | null>(null)
  const [selectedDatabase, setSelectedDatabase] = useState<string>('')
  const [selectedTable, setSelectedTable] = useState<string>('')
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(50)

  // Fetch clusters
  const { data: clustersData, isLoading: clustersLoading } = useQuery({
    queryKey: ['explorer', 'clusters'],
    queryFn: async () => {
      const response = await apiClient.get('/api/v1/explorer/clusters')
      return response.data
    },
  })

  // Fetch databases
  const { data: dbsData, isLoading: dbsLoading } = useQuery({
    queryKey: ['explorer', 'dbs', selectedCluster],
    queryFn: async () => {
      if (!selectedCluster) return null
      const response = await apiClient.get(`/api/v1/explorer/clusters/${selectedCluster}/dbs`)
      return response.data
    },
    enabled: !!selectedCluster,
  })

  // Fetch table data
  const { data: tableData, isLoading: tableLoading, error: tableError } = useQuery({
    queryKey: ['explorer', 'query', selectedCluster, selectedTable, page, perPage],
    queryFn: async () => {
      if (!selectedCluster || !selectedTable) return null
      const response = await apiClient.get('/api/v1/explorer/query', {
        params: {
          resource_id: selectedCluster,
          table: selectedTable,
          page,
          per_page: perPage,
        },
      })
      return response.data as QueryResult
    },
    enabled: !!selectedCluster && !!selectedTable,
  })

  const clusters = clustersData?.clusters || []
  const databases = dbsData?.databases || []

  return (
    <div className="space-y-6 p-8">
      {/* Header */}
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <Database className="h-8 w-8 text-blue-600" />
          <h1 className="text-3xl font-bold">Database Explorer</h1>
        </div>
        <p className="text-gray-600">Browse database schemas and tables (read-only)</p>
      </div>

      {/* Selectors */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="space-y-2">
          <label className="block text-sm font-medium">Cluster</label>
          <select
            value={selectedCluster || ''}
            onChange={(e) => {
              setSelectedCluster(e.target.value ? Number(e.target.value) : null)
              setSelectedDatabase('')
              setSelectedTable('')
            }}
            className="w-full px-3 py-2 border rounded-md"
            disabled={clustersLoading}
          >
            <option value="">Select Cluster...</option>
            {clusters.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </div>

        <div className="space-y-2">
          <label className="block text-sm font-medium">Database</label>
          <select
            value={selectedDatabase}
            onChange={(e) => {
              setSelectedDatabase(e.target.value)
              setSelectedTable('')
            }}
            className="w-full px-3 py-2 border rounded-md"
            disabled={!selectedCluster || dbsLoading}
          >
            <option value="">Select Database...</option>
            {databases.map((db) => (
              <option key={db.name} value={db.name}>
                {db.name}
              </option>
            ))}
          </select>
        </div>

        <div className="space-y-2">
          <label className="block text-sm font-medium">Table</label>
          <Input
            placeholder="Enter table name..."
            value={selectedTable}
            onChange={(e) => {
              setSelectedTable(e.target.value)
              setPage(1)
            }}
            disabled={!selectedDatabase}
          />
        </div>
      </div>

      {/* Results Table */}
      {tableError ? (
        <Card className="border-red-200 bg-red-50">
          <CardContent className="pt-6">
            <p className="text-red-700">Error loading table: {(tableError as any).message}</p>
          </CardContent>
        </Card>
      ) : tableLoading ? (
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-center py-8">
              <div className="text-gray-500">Loading...</div>
            </div>
          </CardContent>
        </Card>
      ) : tableData ? (
        <Card>
          <CardHeader>
            <CardTitle>{tableData.table}</CardTitle>
            <CardDescription>
              Rows {Math.max(1, (page - 1) * perPage + 1)}-{Math.min(page * perPage, tableData.total_rows)} of{' '}
              {tableData.total_rows}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm border-collapse">
                <thead className="bg-gray-100 border-b">
                  <tr>
                    {tableData.columns.map((col) => (
                      <th key={col.name} className="px-4 py-2 text-left font-medium">
                        <div className="flex items-center gap-2">
                          <span>{col.name}</span>
                          {col.pii && (
                            <span title={`PII Type: ${col.pii_type}`} className="text-red-500">
                              🔒
                            </span>
                          )}
                        </div>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {tableData.rows.map((row, idx) => (
                    <tr key={idx} className="border-b hover:bg-gray-50">
                      {tableData.columns.map((col) => (
                        <td key={col.name} className="px-4 py-2">
                          <span className={col.masked ? 'text-gray-400 italic' : ''}>
                            {row[col.name] === null ? '(null)' : String(row[col.name])}
                          </span>
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-between mt-6 pt-4 border-t">
              <div className="text-sm text-gray-600">
                Records per page:
                <select
                  value={perPage}
                  onChange={(e) => {
                    setPerPage(Number(e.target.value))
                    setPage(1)
                  }}
                  className="ml-2 px-2 py-1 border rounded"
                >
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </div>

              <div className="flex items-center gap-2">
                <Button
                  disabled={page === 1}
                  onClick={() => setPage(page - 1)}
                  variant="outline"
                  size="sm"
                >
                  <ChevronLeft className="h-4 w-4" />
                  Prev
                </Button>

                <span className="px-4 py-2">Page {page}</span>

                <Button
                  disabled={page * perPage >= tableData.total_rows}
                  onClick={() => setPage(page + 1)}
                  variant="outline"
                  size="sm"
                >
                  Next
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      ) : selectedTable ? (
        <Card>
          <CardContent className="pt-6">
            <p className="text-gray-500">Select a cluster and database to view results</p>
          </CardContent>
        </Card>
      ) : null}

      {/* PII Warning */}
      {tableData?.pii_detected && !tableData.pii_access_granted && (
        <Card className="border-amber-200 bg-amber-50">
          <CardContent className="pt-6">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-amber-600 mt-0.5 flex-shrink-0" />
              <div className="flex-1">
                <h3 className="font-semibold text-amber-900">PII Fields Detected</h3>
                <p className="text-sm text-amber-800 mt-1">
                  The following fields contain sensitive data and are masked:
                  {tableData.columns
                    .filter((c) => c.pii)
                    .map((c) => `${c.name} (${c.pii_type})`)
                    .join(', ')}
                </p>
                <Button className="mt-3" size="sm" variant="outline">
                  Request PII Access
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
