package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/penguintechinc/articdbm/proxy/internal/auth"
	"github.com/penguintechinc/articdbm/proxy/internal/cache"
	"github.com/penguintechinc/articdbm/proxy/internal/config"
	"github.com/penguintechinc/articdbm/proxy/internal/metrics"
	"github.com/penguintechinc/articdbm/proxy/internal/multiwrite"
	"github.com/penguintechinc/articdbm/proxy/internal/security"
	"github.com/penguintechinc/articdbm/proxy/internal/xdp"
	"github.com/go-redis/redis/v8"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

// SQLiteConfig contains SQLite-specific configuration
type SQLiteConfig struct {
	Path           string `json:"path"`            // Database file path or :memory:
	Name           string `json:"name"`            // Logical database name
	ReadOnly       bool   `json:"read_only"`       // Open in read-only mode
	WALMode        bool   `json:"wal_mode"`        // Enable Write-Ahead Logging
	BusyTimeout    int    `json:"busy_timeout"`    // Busy timeout in milliseconds
	CacheSize      int    `json:"cache_size"`      // Page cache size in KB
	JournalMode    string `json:"journal_mode"`    // Journal mode (DELETE, TRUNCATE, PERSIST, MEMORY, WAL, OFF)
	Synchronous    string `json:"synchronous"`     // Synchronous mode (OFF, NORMAL, FULL, EXTRA)
	ForeignKeys    bool   `json:"foreign_keys"`    // Enable foreign key constraints
	MaxConnections int    `json:"max_connections"` // Maximum concurrent connections
}

// SQLiteHandler handles SQLite database connections
type SQLiteHandler struct {
	*BaseHandler
	databases   map[string]*SQLiteDatabase // name -> database
	dbMu        sync.RWMutex
	authManager *auth.Manager
	secChecker  *security.SQLChecker
}

// SQLiteDatabase represents a single SQLite database instance
type SQLiteDatabase struct {
	config     SQLiteConfig
	db         *sql.DB
	mu         sync.RWMutex
	lastAccess time.Time
	queryCount uint64
	errorCount uint64
}

// NewSQLiteHandler creates a new SQLite handler
func NewSQLiteHandler(cfg *config.Config, redis *redis.Client, logger *zap.Logger,
	xdpController *xdp.Controller, cacheManager *cache.MultiTierCache,
	multiwriteManager *multiwrite.Manager) *SQLiteHandler {

	handler := &SQLiteHandler{
		BaseHandler: NewBaseHandler(cfg, redis, logger, xdpController, cacheManager, multiwriteManager),
		databases:   make(map[string]*SQLiteDatabase),
		authManager: auth.NewManager(cfg, redis, logger),
		secChecker:  security.NewSQLChecker(cfg.SQLInjectionDetection, redis),
	}

	// Seed default blocked resources if enabled
	if cfg.SeedDefaultBlocked {
		ctx := context.Background()
		if err := handler.secChecker.SeedDefaultBlockedResources(ctx); err != nil {
			logger.Warn("Failed to seed default blocked resources", zap.Error(err))
		}
	}

	return handler
}

// Start begins handling SQLite connections
func (h *SQLiteHandler) Start(ctx context.Context, listener net.Listener) {
	// Initialize configured databases
	h.initDatabases()

	// Start periodic maintenance
	go h.maintenanceLoop(ctx)

	for {
		select {
		case <-ctx.Done():
			h.closeDatabases()
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					h.logger.Error("Failed to accept connection", zap.Error(err))
					continue
				}
			}

			go h.handleConnection(ctx, conn)
		}
	}
}

// initDatabases initializes all configured SQLite databases
func (h *SQLiteHandler) initDatabases() {
	h.dbMu.Lock()
	defer h.dbMu.Unlock()

	// Get SQLite configurations from config
	sqliteConfigs := h.getSQLiteConfigs()

	for _, config := range sqliteConfigs {
		if err := h.initDatabase(config); err != nil {
			h.logger.Error("Failed to initialize SQLite database",
				zap.String("name", config.Name),
				zap.String("path", config.Path),
				zap.Error(err))
			continue
		}

		h.logger.Info("Initialized SQLite database",
			zap.String("name", config.Name),
			zap.String("path", config.Path),
			zap.Bool("read_only", config.ReadOnly),
			zap.Bool("wal_mode", config.WALMode))
	}
}

// initDatabase initializes a single SQLite database
func (h *SQLiteHandler) initDatabase(config SQLiteConfig) error {
	// Build connection string
	dsn := h.buildDSN(config)

	// Open database connection
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	if config.MaxConnections > 0 {
		db.SetMaxOpenConns(config.MaxConnections)
		db.SetMaxIdleConns(config.MaxConnections / 2)
	} else {
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
	}
	db.SetConnMaxLifetime(time.Hour)

	// Apply PRAGMA settings
	if err := h.applyPragmas(db, config); err != nil {
		db.Close()
		return fmt.Errorf("failed to apply pragmas: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Store database
	sqliteDB := &SQLiteDatabase{
		config:     config,
		db:         db,
		lastAccess: time.Now(),
	}

	h.databases[config.Name] = sqliteDB

	// Initialize metrics
	metrics.SetSQLiteStatus(config.Name, "connected")

	return nil
}

// buildDSN builds the SQLite connection string
func (h *SQLiteHandler) buildDSN(config SQLiteConfig) string {
	params := []string{}

	// Handle special paths
	path := config.Path
	if path == ":memory:" {
		// In-memory database
		params = append(params, "mode=memory")
	} else {
		// File-based database
		if !filepath.IsAbs(path) {
			// Make path absolute
			absPath, _ := filepath.Abs(path)
			path = absPath
		}

		// Create directory if needed
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			h.logger.Warn("Failed to create database directory",
				zap.String("dir", dir),
				zap.Error(err))
		}

		// Set mode
		if config.ReadOnly {
			params = append(params, "mode=ro")
		} else {
			params = append(params, "mode=rwc")
		}
	}

	// Set cache mode
	if path != ":memory:" {
		params = append(params, "cache=shared")
	}

	// Set busy timeout
	if config.BusyTimeout > 0 {
		params = append(params, fmt.Sprintf("_busy_timeout=%d", config.BusyTimeout))
	} else {
		params = append(params, "_busy_timeout=5000")
	}

	// Build final DSN
	if len(params) > 0 {
		return fmt.Sprintf("file:%s?%s", path, strings.Join(params, "&"))
	}
	return path
}

// applyPragmas applies PRAGMA settings to the database
func (h *SQLiteHandler) applyPragmas(db *sql.DB, config SQLiteConfig) error {
	pragmas := []string{}

	// Journal mode
	if config.JournalMode != "" {
		pragmas = append(pragmas, fmt.Sprintf("PRAGMA journal_mode = %s", config.JournalMode))
	} else if config.WALMode {
		pragmas = append(pragmas, "PRAGMA journal_mode = WAL")
	}

	// Synchronous mode
	if config.Synchronous != "" {
		pragmas = append(pragmas, fmt.Sprintf("PRAGMA synchronous = %s", config.Synchronous))
	} else {
		pragmas = append(pragmas, "PRAGMA synchronous = NORMAL")
	}

	// Cache size
	if config.CacheSize > 0 {
		pragmas = append(pragmas, fmt.Sprintf("PRAGMA cache_size = -%d", config.CacheSize))
	} else {
		pragmas = append(pragmas, "PRAGMA cache_size = -64000") // 64MB default
	}

	// Foreign keys
	if config.ForeignKeys {
		pragmas = append(pragmas, "PRAGMA foreign_keys = ON")
	}

	// Additional optimizations
	pragmas = append(pragmas,
		"PRAGMA temp_store = MEMORY",
		"PRAGMA mmap_size = 268435456", // 256MB memory-mapped I/O
		"PRAGMA page_size = 4096",
		"PRAGMA optimize",
	)

	// Apply all pragmas
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			h.logger.Warn("Failed to apply pragma",
				zap.String("pragma", pragma),
				zap.Error(err))
			// Continue with other pragmas
		}
	}

	return nil
}

// handleConnection handles a client connection
func (h *SQLiteHandler) handleConnection(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	metrics.IncConnection("sqlite")
	defer metrics.DecConnection("sqlite")

	// For SQLite, we use a simplified protocol since it's typically embedded
	// This would need to be adapted based on your specific protocol requirements

	username, database, err := h.performHandshake(clientConn)
	if err != nil {
		h.logger.Error("Handshake failed", zap.Error(err))
		return
	}

	// Authenticate
	if !h.authManager.Authenticate(ctx, username, database, "sqlite") {
		h.logger.Warn("Authentication failed",
			zap.String("user", username),
			zap.String("database", database))
		h.sendError(clientConn, "Access denied")
		return
	}

	// Get database
	sqliteDB, err := h.getDatabase(database)
	if err != nil {
		h.logger.Error("Database not found",
			zap.String("database", database),
			zap.Error(err))
		h.sendError(clientConn, "Database not found")
		return
	}

	// Handle queries
	h.proxyTraffic(ctx, clientConn, sqliteDB, username, database)
}

// getDatabase retrieves a SQLite database by name
func (h *SQLiteHandler) getDatabase(name string) (*SQLiteDatabase, error) {
	h.dbMu.RLock()
	defer h.dbMu.RUnlock()

	db, ok := h.databases[name]
	if !ok {
		return nil, fmt.Errorf("database %s not found", name)
	}

	// Update last access time
	db.mu.Lock()
	db.lastAccess = time.Now()
	db.mu.Unlock()

	return db, nil
}

// proxyTraffic handles query traffic for SQLite
func (h *SQLiteHandler) proxyTraffic(ctx context.Context, client net.Conn,
	sqliteDB *SQLiteDatabase, username, database string) {

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := client.Read(buf)
			if err != nil {
				return
			}

			query := string(buf[:n])

			// Check if database is read-only
			if sqliteDB.config.ReadOnly && h.isWriteQuery(query) {
				h.logger.Warn("Write query on read-only database",
					zap.String("database", database),
					zap.String("query", query[:min(100, len(query))]))
				h.sendError(client, "Database is read-only")
				continue
			}

			// Security checks
			if h.cfg.BlockingEnabled {
				if blocked, reason := h.secChecker.IsBlockedConnection(ctx, database, "", username); blocked {
					h.logger.Warn("Blocked resource access",
						zap.String("user", username),
						zap.String("database", database),
						zap.String("reason", reason))
					h.sendError(client, "Access blocked: "+reason)
					return
				}
			}

			// SQL injection check
			if isMalicious, attackType, description := h.secChecker.IsSQLInjectionWithDetails(query); isMalicious {
				h.logger.Warn("Security threat detected",
					zap.String("user", username),
					zap.String("database", database),
					zap.String("attack_type", attackType),
					zap.String("description", description))
				metrics.IncSQLInjection("sqlite")
				h.sendError(client, "Query blocked: "+attackType)
				continue
			}

			// Authorization check
			if !h.authManager.Authorize(ctx, username, database, "", h.isWriteQuery(query)) {
				h.logger.Warn("Unauthorized query",
					zap.String("user", username),
					zap.String("database", database))
				h.sendError(client, "Unauthorized")
				continue
			}

			// Execute query
			result, err := h.executeQuery(ctx, sqliteDB, query)
			if err != nil {
				h.logger.Error("Query execution failed",
					zap.String("database", database),
					zap.Error(err))
				sqliteDB.mu.Lock()
				sqliteDB.errorCount++
				sqliteDB.mu.Unlock()
				h.sendError(client, err.Error())
				continue
			}

			// Update metrics
			sqliteDB.mu.Lock()
			sqliteDB.queryCount++
			sqliteDB.mu.Unlock()
			metrics.IncQuery("sqlite", h.isWriteQuery(query))

			// Send result (simplified for example)
			client.Write([]byte(result))
		}
	}
}

// executeQuery executes a query on the SQLite database
func (h *SQLiteHandler) executeQuery(ctx context.Context, sqliteDB *SQLiteDatabase, query string) (string, error) {
	// This is a simplified implementation
	// In production, you'd need proper result serialization

	rows, err := sqliteDB.db.QueryContext(ctx, query)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	// For demonstration, return row count
	count := 0
	for rows.Next() {
		count++
	}

	return fmt.Sprintf("OK: %d rows", count), nil
}

// performHandshake performs a simplified handshake
func (h *SQLiteHandler) performHandshake(conn net.Conn) (string, string, error) {
	// This is a simplified handshake for SQLite
	// You would implement your actual protocol here

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", "", err
	}

	// Parse simple format: username:database
	parts := strings.Split(string(buf[:n]), ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid handshake")
	}

	// Send acknowledgment
	conn.Write([]byte("OK"))

	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
}

// sendError sends an error message to the client
func (h *SQLiteHandler) sendError(conn net.Conn, message string) {
	conn.Write([]byte(fmt.Sprintf("ERROR: %s", message)))
}

// isWriteQuery checks if a query is a write operation
func (h *SQLiteHandler) isWriteQuery(query string) bool {
	return security.IsWriteQuery(query)
}

// getSQLiteConfigs gets SQLite configurations from the main config
func (h *SQLiteHandler) getSQLiteConfigs() []SQLiteConfig {
	// This would be populated from your main configuration
	// For now, return example configurations

	configs := []SQLiteConfig{
		{
			Name:           "main",
			Path:           "/data/articdbm/main.db",
			ReadOnly:       false,
			WALMode:        true,
			BusyTimeout:    5000,
			CacheSize:      64000,
			JournalMode:    "WAL",
			Synchronous:    "NORMAL",
			ForeignKeys:    true,
			MaxConnections: 10,
		},
		{
			Name:           "cache",
			Path:           ":memory:",
			ReadOnly:       false,
			WALMode:        false,
			BusyTimeout:    1000,
			CacheSize:      32000,
			MaxConnections: 20,
		},
		{
			Name:           "reference",
			Path:           "/data/articdbm/reference.db",
			ReadOnly:       true,
			WALMode:        false,
			BusyTimeout:    5000,
			CacheSize:      16000,
			MaxConnections: 50,
		},
	}

	// Override with environment variables if present
	if sqlitePath := os.Getenv("SQLITE_PATH"); sqlitePath != "" {
		configs[0].Path = sqlitePath
	}

	return configs
}

// maintenanceLoop performs periodic maintenance tasks
func (h *SQLiteHandler) maintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.performMaintenance()
		}
	}
}

// performMaintenance performs database maintenance
func (h *SQLiteHandler) performMaintenance() {
	h.dbMu.RLock()
	databases := make([]*SQLiteDatabase, 0, len(h.databases))
	for _, db := range h.databases {
		databases = append(databases, db)
	}
	h.dbMu.RUnlock()

	for _, sqliteDB := range databases {
		// Run VACUUM if needed (only on non-memory databases)
		if sqliteDB.config.Path != ":memory:" {
			// Check if VACUUM is needed (simplified check)
			sqliteDB.mu.RLock()
			errorRate := float64(sqliteDB.errorCount) / float64(sqliteDB.queryCount+1)
			sqliteDB.mu.RUnlock()

			if errorRate > 0.01 { // More than 1% errors
				h.logger.Info("Running VACUUM on database",
					zap.String("name", sqliteDB.config.Name))

				if _, err := sqliteDB.db.Exec("VACUUM"); err != nil {
					h.logger.Error("VACUUM failed",
						zap.String("name", sqliteDB.config.Name),
						zap.Error(err))
				}
			}
		}

		// Run ANALYZE periodically
		if _, err := sqliteDB.db.Exec("ANALYZE"); err != nil {
			h.logger.Warn("ANALYZE failed",
				zap.String("name", sqliteDB.config.Name),
				zap.Error(err))
		}

		// Update metrics
		sqliteDB.mu.RLock()
		metrics.SetSQLiteQueryCount(sqliteDB.config.Name, float64(sqliteDB.queryCount))
		metrics.SetSQLiteErrorCount(sqliteDB.config.Name, float64(sqliteDB.errorCount))
		sqliteDB.mu.RUnlock()
	}
}

// closeDatabases closes all SQLite databases
func (h *SQLiteHandler) closeDatabases() {
	h.dbMu.Lock()
	defer h.dbMu.Unlock()

	for name, sqliteDB := range h.databases {
		if err := sqliteDB.db.Close(); err != nil {
			h.logger.Error("Failed to close database",
				zap.String("name", name),
				zap.Error(err))
		}
		metrics.SetSQLiteStatus(name, "disconnected")
	}

	h.databases = make(map[string]*SQLiteDatabase)
}

// GetDatabaseStatus returns the status of all SQLite databases
func (h *SQLiteHandler) GetDatabaseStatus() map[string]interface{} {
	h.dbMu.RLock()
	defer h.dbMu.RUnlock()

	status := make(map[string]interface{})

	for name, sqliteDB := range h.databases {
		sqliteDB.mu.RLock()
		dbStatus := map[string]interface{}{
			"path":         sqliteDB.config.Path,
			"read_only":    sqliteDB.config.ReadOnly,
			"wal_mode":     sqliteDB.config.WALMode,
			"last_access":  sqliteDB.lastAccess,
			"query_count":  sqliteDB.queryCount,
			"error_count":  sqliteDB.errorCount,
			"error_rate":   float64(sqliteDB.errorCount) / float64(sqliteDB.queryCount+1),
		}
		sqliteDB.mu.RUnlock()

		// Get database statistics
		var pageCount, pageSize, cacheSize int
		sqliteDB.db.QueryRow("PRAGMA page_count").Scan(&pageCount)
		sqliteDB.db.QueryRow("PRAGMA page_size").Scan(&pageSize)
		sqliteDB.db.QueryRow("PRAGMA cache_size").Scan(&cacheSize)

		dbStatus["page_count"] = pageCount
		dbStatus["page_size"] = pageSize
		dbStatus["cache_size"] = cacheSize
		dbStatus["size_bytes"] = pageCount * pageSize

		status[name] = dbStatus
	}

	return status
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}