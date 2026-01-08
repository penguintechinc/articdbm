package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// SQLite database metrics
	sqliteStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_sqlite_status",
			Help: "SQLite database connection status (0=disconnected, 1=connected)",
		},
		[]string{"database"},
	)

	sqliteQueryCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_sqlite_query_total",
			Help: "Total number of queries executed on SQLite database",
		},
		[]string{"database"},
	)

	sqliteErrorCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_sqlite_error_total",
			Help: "Total number of errors on SQLite database",
		},
		[]string{"database"},
	)

	sqliteDatabaseSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_sqlite_database_size_bytes",
			Help: "SQLite database file size in bytes",
		},
		[]string{"database"},
	)

	sqlitePageCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_sqlite_page_count",
			Help: "Number of pages in SQLite database",
		},
		[]string{"database"},
	)

	sqliteCacheHitRatio = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_sqlite_cache_hit_ratio",
			Help: "SQLite page cache hit ratio",
		},
		[]string{"database"},
	)

	sqliteWALCheckpoints = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "articdbm_sqlite_wal_checkpoints_total",
			Help: "Total number of WAL checkpoints performed",
		},
		[]string{"database"},
	)

	sqliteVacuumOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "articdbm_sqlite_vacuum_operations_total",
			Help: "Total number of VACUUM operations performed",
		},
		[]string{"database"},
	)

	sqliteTransactionCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "articdbm_sqlite_transactions_total",
			Help: "Total number of transactions",
		},
		[]string{"database", "status"}, // status: committed, rolled_back
	)

	sqliteConnectionPool = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_sqlite_connection_pool_size",
			Help: "Current connection pool size for SQLite database",
		},
		[]string{"database", "state"}, // state: active, idle
	)
)

// SetSQLiteStatus sets the connection status for a SQLite database
func SetSQLiteStatus(database string, status string) {
	value := 0.0
	if status == "connected" {
		value = 1.0
	}
	sqliteStatus.WithLabelValues(database).Set(value)
}

// SetSQLiteQueryCount sets the total query count for a database
func SetSQLiteQueryCount(database string, count float64) {
	sqliteQueryCount.WithLabelValues(database).Set(count)
}

// SetSQLiteErrorCount sets the total error count for a database
func SetSQLiteErrorCount(database string, count float64) {
	sqliteErrorCount.WithLabelValues(database).Set(count)
}

// SetSQLiteDatabaseSize sets the database file size
func SetSQLiteDatabaseSize(database string, bytes float64) {
	sqliteDatabaseSize.WithLabelValues(database).Set(bytes)
}

// SetSQLitePageCount sets the page count for a database
func SetSQLitePageCount(database string, count float64) {
	sqlitePageCount.WithLabelValues(database).Set(count)
}

// SetSQLiteCacheHitRatio sets the cache hit ratio
func SetSQLiteCacheHitRatio(database string, ratio float64) {
	sqliteCacheHitRatio.WithLabelValues(database).Set(ratio)
}

// IncSQLiteWALCheckpoint increments the WAL checkpoint counter
func IncSQLiteWALCheckpoint(database string) {
	sqliteWALCheckpoints.WithLabelValues(database).Inc()
}

// IncSQLiteVacuum increments the VACUUM operation counter
func IncSQLiteVacuum(database string) {
	sqliteVacuumOperations.WithLabelValues(database).Inc()
}

// IncSQLiteTransaction increments the transaction counter
func IncSQLiteTransaction(database, status string) {
	sqliteTransactionCount.WithLabelValues(database, status).Inc()
}

// SetSQLiteConnectionPool sets the connection pool metrics
func SetSQLiteConnectionPool(database string, active, idle float64) {
	sqliteConnectionPool.WithLabelValues(database, "active").Set(active)
	sqliteConnectionPool.WithLabelValues(database, "idle").Set(idle)
}