package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/penguintechinc/articdbm/proxy/internal/auth"
	"github.com/penguintechinc/articdbm/proxy/internal/config"
	"github.com/penguintechinc/articdbm/proxy/internal/metrics"
	"github.com/penguintechinc/articdbm/proxy/internal/pool"
	"github.com/penguintechinc/articdbm/proxy/internal/security"
	"github.com/penguintechinc/articdbm/proxy/internal/cache"
	"github.com/penguintechinc/articdbm/proxy/internal/multiwrite"
	"github.com/penguintechinc/articdbm/proxy/internal/xdp"
	"github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
)

// GaleraNodeState represents the state of a Galera cluster node
type GaleraNodeState int

const (
	GaleraStateUndefined     GaleraNodeState = 0 // Node is undefined
	GaleraStateJoining       GaleraNodeState = 1 // Node is joining cluster
	GaleraStateDonor         GaleraNodeState = 2 // Node is donor/desynced
	GaleraStateJoined        GaleraNodeState = 3 // Node has joined cluster
	GaleraStateSynced        GaleraNodeState = 4 // Node is synced (ready)
	GaleraStateError         GaleraNodeState = 5 // Node is in error state
	GaleraStateDisconnected  GaleraNodeState = 6 // Node disconnected
)

func (s GaleraNodeState) String() string {
	switch s {
	case GaleraStateUndefined:
		return "Undefined"
	case GaleraStateJoining:
		return "Joining"
	case GaleraStateDonor:
		return "Donor/Desynced"
	case GaleraStateJoined:
		return "Joined"
	case GaleraStateSynced:
		return "Synced"
	case GaleraStateError:
		return "Error"
	case GaleraStateDisconnected:
		return "Disconnected"
	default:
		return "Unknown"
	}
}

// GaleraNodeInfo contains information about a Galera cluster node
type GaleraNodeInfo struct {
	Backend              *config.Backend
	State                GaleraNodeState
	Ready                bool
	LocalIndex           int64
	ClusterSize          int64
	ClusterStatus        string
	FlowControlPaused    bool
	FlowControlSent      int64
	FlowControlReceived  int64
	LastUpdated          time.Time
	CertFailures         int64
	LocalCommits         int64
	LocalReplays         int64
	ConnectErrors        int
	ConsecutiveErrors    int
	Weight               float64
	ReplicationLatency   time.Duration
	LastHealthCheck      time.Time
}

// IsHealthy returns true if the node is in a healthy state for serving queries
func (n *GaleraNodeInfo) IsHealthy() bool {
	return n.Ready &&
		   n.State == GaleraStateSynced &&
		   !n.FlowControlPaused &&
		   n.ConsecutiveErrors < 3 &&
		   time.Since(n.LastHealthCheck) < 30*time.Second
}

// CanServeReads returns true if the node can serve read queries
func (n *GaleraNodeInfo) CanServeReads() bool {
	return n.IsHealthy() || (n.State == GaleraStateJoined && !n.FlowControlPaused)
}

// CanServeWrites returns true if the node can serve write queries
func (n *GaleraNodeInfo) CanServeWrites() bool {
	return n.IsHealthy()
}

// GaleraHandler handles MariaDB Galera Cluster connections with cluster-aware routing
type GaleraHandler struct {
	*BaseHandler
	pools           map[string]*pool.ConnectionPool
	nodeInfo        map[string]*GaleraNodeInfo
	poolMu          sync.RWMutex
	nodeInfoMu      sync.RWMutex
	authManager     *auth.Manager
	secChecker      *security.SQLChecker
	healthCheckTicker *time.Ticker
	stopHealthCheck chan bool

	// Galera-specific configuration
	healthCheckInterval     time.Duration
	maxConsecutiveErrors    int
	flowControlThreshold    int64
	readOnlyNodes          bool // Allow reads from non-synced nodes
	writeBalancing         bool // Balance writes across all synced nodes
	nodeWeightEnabled      bool // Use node weights for load balancing
}

// GaleraConfig contains Galera-specific configuration
type GaleraConfig struct {
	HealthCheckInterval     time.Duration `json:"health_check_interval"`
	MaxConsecutiveErrors    int           `json:"max_consecutive_errors"`
	FlowControlThreshold    int64         `json:"flow_control_threshold"`
	ReadOnlyNodes          bool          `json:"read_only_nodes"`
	WriteBalancing         bool          `json:"write_balancing"`
	NodeWeightEnabled      bool          `json:"node_weight_enabled"`
	ConnectionTimeout      time.Duration `json:"connection_timeout"`
	QueryTimeout           time.Duration `json:"query_timeout"`
}

func NewGaleraHandler(cfg *config.Config, redis *redis.Client, logger *zap.Logger,
	xdpController *xdp.Controller, cacheManager *cache.MultiTierCache,
	multiwriteManager *multiwrite.Manager) *GaleraHandler {

	// Default Galera configuration
	galeraConfig := GaleraConfig{
		HealthCheckInterval:  10 * time.Second,
		MaxConsecutiveErrors: 3,
		FlowControlThreshold: 100,
		ReadOnlyNodes:       false,
		WriteBalancing:      true,
		NodeWeightEnabled:   true,
		ConnectionTimeout:   5 * time.Second,
		QueryTimeout:       30 * time.Second,
	}

	// Override with config values if available
	if cfg.GaleraConfig != nil {
		if interval, ok := cfg.GaleraConfig["health_check_interval"].(time.Duration); ok {
			galeraConfig.HealthCheckInterval = interval
		}
		if errors, ok := cfg.GaleraConfig["max_consecutive_errors"].(int); ok {
			galeraConfig.MaxConsecutiveErrors = errors
		}
		if threshold, ok := cfg.GaleraConfig["flow_control_threshold"].(int64); ok {
			galeraConfig.FlowControlThreshold = threshold
		}
		if readOnly, ok := cfg.GaleraConfig["read_only_nodes"].(bool); ok {
			galeraConfig.ReadOnlyNodes = readOnly
		}
		if writeBalance, ok := cfg.GaleraConfig["write_balancing"].(bool); ok {
			galeraConfig.WriteBalancing = writeBalance
		}
		if nodeWeight, ok := cfg.GaleraConfig["node_weight_enabled"].(bool); ok {
			galeraConfig.NodeWeightEnabled = nodeWeight
		}
	}

	handler := &GaleraHandler{
		BaseHandler:           NewBaseHandler(cfg, redis, logger, xdpController, cacheManager, multiwriteManager),
		pools:                make(map[string]*pool.ConnectionPool),
		nodeInfo:             make(map[string]*GaleraNodeInfo),
		authManager:          auth.NewManager(cfg, redis, logger),
		secChecker:           security.NewSQLChecker(cfg.SQLInjectionDetection, redis),
		healthCheckInterval:  galeraConfig.HealthCheckInterval,
		maxConsecutiveErrors: galeraConfig.MaxConsecutiveErrors,
		flowControlThreshold: galeraConfig.FlowControlThreshold,
		readOnlyNodes:       galeraConfig.ReadOnlyNodes,
		writeBalancing:      galeraConfig.WriteBalancing,
		nodeWeightEnabled:   galeraConfig.NodeWeightEnabled,
		stopHealthCheck:     make(chan bool),
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

func (h *GaleraHandler) Start(ctx context.Context, listener net.Listener) {
	h.initPools()
	h.startHealthChecks(ctx)

	for {
		select {
		case <-ctx.Done():
			h.stopHealthChecks()
			h.closePools()
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

func (h *GaleraHandler) initPools() {
	h.poolMu.Lock()
	defer h.poolMu.Unlock()

	for _, backend := range h.cfg.MySQLBackends {
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?timeout=%s&readTimeout=%s&writeTimeout=%s",
			backend.User, backend.Password, backend.Host, backend.Port, backend.Database,
			h.healthCheckInterval.String(), h.healthCheckInterval.String(), h.healthCheckInterval.String())

		if backend.TLS {
			dsn += "&tls=true"
		}

		// Add Galera-specific connection parameters
		dsn += "&autocommit=true&sql_mode=STRICT_TRANS_TABLES"

		p := pool.NewConnectionPool("mysql", dsn, h.cfg.MaxConnections/len(h.cfg.MySQLBackends))
		key := fmt.Sprintf("%s:%d", backend.Host, backend.Port)
		h.pools[key] = p

		// Initialize node info
		h.nodeInfoMu.Lock()
		h.nodeInfo[key] = &GaleraNodeInfo{
			Backend:       &backend,
			State:         GaleraStateUndefined,
			Ready:         false,
			Weight:        backend.Weight,
			LastUpdated:   time.Now(),
		}
		h.nodeInfoMu.Unlock()
	}
}

func (h *GaleraHandler) startHealthChecks(ctx context.Context) {
	h.healthCheckTicker = time.NewTicker(h.healthCheckInterval)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-h.stopHealthCheck:
				return
			case <-h.healthCheckTicker.C:
				h.performHealthChecks(ctx)
			}
		}
	}()

	// Perform initial health check
	go h.performHealthChecks(ctx)
}

func (h *GaleraHandler) stopHealthChecks() {
	if h.healthCheckTicker != nil {
		h.healthCheckTicker.Stop()
	}
	close(h.stopHealthCheck)
}

func (h *GaleraHandler) performHealthChecks(ctx context.Context) {
	h.nodeInfoMu.RLock()
	nodes := make(map[string]*GaleraNodeInfo)
	for k, v := range h.nodeInfo {
		nodes[k] = v
	}
	h.nodeInfoMu.RUnlock()

	var wg sync.WaitGroup
	for key, node := range nodes {
		wg.Add(1)
		go func(k string, n *GaleraNodeInfo) {
			defer wg.Done()
			h.checkNodeHealth(ctx, k, n)
		}(key, node)
	}
	wg.Wait()
}

func (h *GaleraHandler) checkNodeHealth(ctx context.Context, key string, node *GaleraNodeInfo) {
	h.poolMu.RLock()
	pool, exists := h.pools[key]
	h.poolMu.RUnlock()

	if !exists {
		h.logger.Warn("Pool not found for node", zap.String("node", key))
		return
	}

	conn, err := pool.Get()
	if err != nil {
		h.updateNodeError(key, node, err)
		return
	}
	defer conn.Close()

	// Query Galera status variables
	queries := []string{
		"SHOW STATUS LIKE 'wsrep_local_state'",
		"SHOW STATUS LIKE 'wsrep_ready'",
		"SHOW STATUS LIKE 'wsrep_local_index'",
		"SHOW STATUS LIKE 'wsrep_cluster_size'",
		"SHOW STATUS LIKE 'wsrep_cluster_status'",
		"SHOW STATUS LIKE 'wsrep_flow_control_paused'",
		"SHOW STATUS LIKE 'wsrep_flow_control_sent'",
		"SHOW STATUS LIKE 'wsrep_flow_control_recv'",
		"SHOW STATUS LIKE 'wsrep_cert_deps_distance'",
		"SHOW STATUS LIKE 'wsrep_local_commits'",
		"SHOW STATUS LIKE 'wsrep_local_cert_failures'",
		"SHOW STATUS LIKE 'wsrep_local_replays'",
	}

	statusMap := make(map[string]string)
	for _, query := range queries {
		rows, err := conn.QueryContext(ctx, query)
		if err != nil {
			h.updateNodeError(key, node, fmt.Errorf("health check query failed: %w", err))
			return
		}

		for rows.Next() {
			var name, value string
			if err := rows.Scan(&name, &value); err != nil {
				rows.Close()
				h.updateNodeError(key, node, fmt.Errorf("scan failed: %w", err))
				return
			}
			statusMap[name] = value
		}
		rows.Close()
	}

	// Update node information
	h.updateNodeInfo(key, node, statusMap)
}

func (h *GaleraHandler) updateNodeInfo(key string, node *GaleraNodeInfo, statusMap map[string]string) {
	h.nodeInfoMu.Lock()
	defer h.nodeInfoMu.Unlock()

	// Parse wsrep_local_state
	if stateStr, ok := statusMap["wsrep_local_state"]; ok {
		if state, err := strconv.Atoi(stateStr); err == nil {
			node.State = GaleraNodeState(state)
		}
	}

	// Parse wsrep_ready
	if readyStr, ok := statusMap["wsrep_ready"]; ok {
		node.Ready = strings.ToUpper(readyStr) == "ON"
	}

	// Parse wsrep_local_index
	if indexStr, ok := statusMap["wsrep_local_index"]; ok {
		if index, err := strconv.ParseInt(indexStr, 10, 64); err == nil {
			node.LocalIndex = index
		}
	}

	// Parse wsrep_cluster_size
	if sizeStr, ok := statusMap["wsrep_cluster_size"]; ok {
		if size, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
			node.ClusterSize = size
		}
	}

	// Parse wsrep_cluster_status
	if status, ok := statusMap["wsrep_cluster_status"]; ok {
		node.ClusterStatus = status
	}

	// Parse flow control information
	if pausedStr, ok := statusMap["wsrep_flow_control_paused"]; ok {
		node.FlowControlPaused = pausedStr != "0"
	}

	if sentStr, ok := statusMap["wsrep_flow_control_sent"]; ok {
		if sent, err := strconv.ParseInt(sentStr, 10, 64); err == nil {
			node.FlowControlSent = sent
		}
	}

	if recvStr, ok := statusMap["wsrep_flow_control_recv"]; ok {
		if recv, err := strconv.ParseInt(recvStr, 10, 64); err == nil {
			node.FlowControlReceived = recv
		}
	}

	// Parse certificate failures
	if certFailStr, ok := statusMap["wsrep_local_cert_failures"]; ok {
		if failures, err := strconv.ParseInt(certFailStr, 10, 64); err == nil {
			node.CertFailures = failures
		}
	}

	// Parse commits and replays
	if commitsStr, ok := statusMap["wsrep_local_commits"]; ok {
		if commits, err := strconv.ParseInt(commitsStr, 10, 64); err == nil {
			node.LocalCommits = commits
		}
	}

	if replaysStr, ok := statusMap["wsrep_local_replays"]; ok {
		if replays, err := strconv.ParseInt(replaysStr, 10, 64); err == nil {
			node.LocalReplays = replays
		}
	}

	// Reset error counters on successful health check
	node.ConsecutiveErrors = 0
	node.LastUpdated = time.Now()
	node.LastHealthCheck = time.Now()

	h.logger.Debug("Updated Galera node info",
		zap.String("node", key),
		zap.String("state", node.State.String()),
		zap.Bool("ready", node.Ready),
		zap.Bool("flow_control_paused", node.FlowControlPaused),
		zap.Int64("cluster_size", node.ClusterSize),
		zap.String("cluster_status", node.ClusterStatus))

	// Update metrics
	metrics.SetGaleraNodeState(key, int(node.State))
	metrics.SetGaleraNodeReady(key, node.Ready)
	metrics.SetGaleraClusterSize(key, float64(node.ClusterSize))
	metrics.SetGaleraFlowControl(key, node.FlowControlPaused)
}

func (h *GaleraHandler) updateNodeError(key string, node *GaleraNodeInfo, err error) {
	h.nodeInfoMu.Lock()
	defer h.nodeInfoMu.Unlock()

	node.ConsecutiveErrors++
	node.ConnectErrors++
	node.LastUpdated = time.Now()

	if node.ConsecutiveErrors >= h.maxConsecutiveErrors {
		node.Ready = false
		node.State = GaleraStateError
	}

	h.logger.Warn("Galera node health check failed",
		zap.String("node", key),
		zap.Error(err),
		zap.Int("consecutive_errors", node.ConsecutiveErrors))

	// Update metrics
	metrics.IncGaleraNodeErrors(key)
	metrics.SetGaleraNodeReady(key, node.Ready)
}

func (h *GaleraHandler) closePools() {
	h.poolMu.Lock()
	defer h.poolMu.Unlock()

	for _, p := range h.pools {
		p.Close()
	}
}

func (h *GaleraHandler) handleConnection(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	metrics.IncConnection("galera")
	defer metrics.DecConnection("galera")

	username, database, err := h.performHandshake(clientConn)
	if err != nil {
		h.logger.Error("Handshake failed", zap.Error(err))
		return
	}

	if !h.authManager.Authenticate(ctx, username, database, "mysql") {
		h.logger.Warn("Authentication failed",
			zap.String("user", username),
			zap.String("database", database))
		h.sendError(clientConn, "Access denied")
		return
	}

	backend := h.selectGaleraBackend(false)
	if backend == nil {
		h.logger.Error("No healthy Galera node available")
		h.sendError(clientConn, "No healthy Galera node available")
		return
	}

	backendConn, err := h.getBackendConnection(backend)
	if err != nil {
		h.logger.Error("Failed to connect to Galera backend", zap.Error(err))
		h.sendError(clientConn, "Backend connection failed")
		return
	}
	defer backendConn.Close()

	h.proxyTraffic(ctx, clientConn, backendConn, username, database)
}

func (h *GaleraHandler) selectGaleraBackend(isWrite bool) *config.Backend {
	h.nodeInfoMu.RLock()
	defer h.nodeInfoMu.RUnlock()

	var candidates []*GaleraNodeInfo

	// Filter nodes based on query type and health
	for _, node := range h.nodeInfo {
		if isWrite {
			if node.CanServeWrites() {
				candidates = append(candidates, node)
			}
		} else {
			if node.CanServeReads() {
				candidates = append(candidates, node)
			} else if h.readOnlyNodes && node.State == GaleraStateJoined && !node.FlowControlPaused {
				candidates = append(candidates, node)
			}
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// Select best node based on configuration
	if h.nodeWeightEnabled {
		return h.selectByWeight(candidates)
	}

	return h.selectByRoundRobin(candidates)
}

func (h *GaleraHandler) selectByWeight(candidates []*GaleraNodeInfo) *config.Backend {
	if len(candidates) == 0 {
		return nil
	}

	// Calculate total weight
	totalWeight := 0.0
	for _, node := range candidates {
		weight := node.Weight
		if weight <= 0 {
			weight = 1.0
		}

		// Adjust weight based on flow control and error rate
		if node.FlowControlPaused {
			weight *= 0.1 // Heavily penalize flow control
		}
		if node.ConsecutiveErrors > 0 {
			weight *= 0.5 // Penalize nodes with recent errors
		}

		totalWeight += weight
	}

	if totalWeight == 0 {
		return candidates[0].Backend
	}

	// Weighted random selection
	r := h.cfg.GetRandomFloat() * totalWeight
	currentWeight := 0.0

	for _, node := range candidates {
		weight := node.Weight
		if weight <= 0 {
			weight = 1.0
		}

		// Apply same adjustments
		if node.FlowControlPaused {
			weight *= 0.1
		}
		if node.ConsecutiveErrors > 0 {
			weight *= 0.5
		}

		currentWeight += weight
		if r <= currentWeight {
			return node.Backend
		}
	}

	return candidates[0].Backend
}

func (h *GaleraHandler) selectByRoundRobin(candidates []*GaleraNodeInfo) *config.Backend {
	if len(candidates) == 0 {
		return nil
	}

	// Simple round-robin selection
	// This could be enhanced with better load balancing algorithms
	index := time.Now().UnixNano() % int64(len(candidates))
	return candidates[index].Backend
}

func (h *GaleraHandler) performHandshake(conn net.Conn) (string, string, error) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", "", err
	}

	if n < 36 {
		return "", "", fmt.Errorf("invalid handshake packet")
	}

	username := ""
	database := ""

	pos := 36
	for pos < n && buf[pos] != 0 {
		username += string(buf[pos])
		pos++
	}
	pos++

	if pos < n {
		pos += 23
		for pos < n && buf[pos] != 0 {
			database += string(buf[pos])
			pos++
		}
	}

	greeting := []byte{
		0x0a, 0x35, 0x2e, 0x37, 0x2e, 0x33, 0x33, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x47, 0x61, 0x6c, 0x65, // "Gale"
		0x72, 0x61, 0x44, 0x42, 0x4d, 0x00, 0x00, 0x00, // "raDBM"
	}
	conn.Write(greeting)

	return username, database, nil
}

func (h *GaleraHandler) sendError(conn net.Conn, message string) {
	errorPacket := []byte{
		0xff,
		0x48, 0x04,
		0x23, 0x48, 0x59, 0x30, 0x30, 0x30,
	}
	errorPacket = append(errorPacket, []byte(message)...)
	conn.Write(errorPacket)
}

func (h *GaleraHandler) getBackendConnection(backend *config.Backend) (*sql.Conn, error) {
	key := fmt.Sprintf("%s:%d", backend.Host, backend.Port)

	h.poolMu.RLock()
	p, ok := h.pools[key]
	h.poolMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("pool not found for backend %s", key)
	}

	return p.Get()
}

func (h *GaleraHandler) proxyTraffic(ctx context.Context, client net.Conn, backend *sql.Conn, username, database string) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
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

				// Check for blocked databases/users/tables if blocking is enabled
				if h.cfg.BlockingEnabled {
					if blocked, reason := h.secChecker.IsBlockedConnection(ctx, database, "", username); blocked {
						h.logger.Warn("Blocked resource access attempt",
							zap.String("user", username),
							zap.String("database", database),
							zap.String("reason", reason),
							zap.String("type", "connection"))
						h.sendError(client, "Access to this resource is blocked: "+reason)
						return
					}
				}

				// Enhanced security check with details
				if isMalicious, attackType, description := h.secChecker.IsSQLInjectionWithDetails(query); isMalicious {
					h.logger.Warn("Security threat detected",
						zap.String("user", username),
						zap.String("database", database),
						zap.String("attack_type", attackType),
						zap.String("description", description),
						zap.String("query", query[:min(100, len(query))]))
					metrics.IncSQLInjection("galera")
					h.sendError(client, "Query blocked by security policy: "+attackType)
					return
				}

				// Check threat intelligence indicators
				sourceIP := client.RemoteAddr().String()
				if matched, indicator, reason := h.secChecker.CheckThreatIntel(ctx, database, sourceIP, query, username); matched {
					h.logger.Warn("Threat intelligence match",
						zap.String("user", username),
						zap.String("database", database),
						zap.String("source_ip", sourceIP),
						zap.String("threat_level", indicator.ThreatLevel),
						zap.String("reason", reason),
						zap.String("query", query[:min(100, len(query))]))
					metrics.IncSQLInjection("galera")
					h.sendError(client, "Query blocked by threat intelligence: "+reason)
					return
				}

				if !h.authManager.Authorize(ctx, username, database, "", h.isWriteQuery(query)) {
					h.logger.Warn("Unauthorized query",
						zap.String("user", username),
						zap.String("database", database))
					h.sendError(client, "Unauthorized")
					return
				}

				metrics.IncQuery("galera", h.isWriteQuery(query))
			}
		}
	}()

	go func() {
		defer wg.Done()
	}()

	wg.Wait()
}

func (h *GaleraHandler) isWriteQuery(query string) bool {
	return security.IsWriteQuery(query)
}

// GetClusterStatus returns the current status of the Galera cluster
func (h *GaleraHandler) GetClusterStatus() map[string]*GaleraNodeInfo {
	h.nodeInfoMu.RLock()
	defer h.nodeInfoMu.RUnlock()

	status := make(map[string]*GaleraNodeInfo)
	for k, v := range h.nodeInfo {
		// Create a copy to avoid race conditions
		nodeCopy := *v
		status[k] = &nodeCopy
	}

	return status
}

// GetHealthyNodes returns a list of healthy nodes that can serve queries
func (h *GaleraHandler) GetHealthyNodes(forWrites bool) []*GaleraNodeInfo {
	h.nodeInfoMu.RLock()
	defer h.nodeInfoMu.RUnlock()

	var healthy []*GaleraNodeInfo
	for _, node := range h.nodeInfo {
		if forWrites {
			if node.CanServeWrites() {
				healthy = append(healthy, node)
			}
		} else {
			if node.CanServeReads() {
				healthy = append(healthy, node)
			}
		}
	}

	return healthy
}