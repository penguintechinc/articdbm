package metrics

import (
	"sync"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Galera cluster metrics
	galeraNodeState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_galera_node_state",
			Help: "Current state of Galera cluster node (0=Undefined, 1=Joining, 2=Donor, 3=Joined, 4=Synced, 5=Error, 6=Disconnected)",
		},
		[]string{"node", "cluster"},
	)

	galeraNodeReady = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_galera_node_ready",
			Help: "Whether Galera node is ready to serve queries (0=Not Ready, 1=Ready)",
		},
		[]string{"node", "cluster"},
	)

	galeraClusterSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_galera_cluster_size",
			Help: "Number of nodes in Galera cluster",
		},
		[]string{"cluster"},
	)

	galeraFlowControl = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_galera_flow_control_paused",
			Help: "Whether Galera node has flow control paused (0=Normal, 1=Paused)",
		},
		[]string{"node", "cluster"},
	)

	galeraFlowControlSent = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "articdbm_galera_flow_control_sent_total",
			Help: "Total number of flow control messages sent by Galera node",
		},
		[]string{"node", "cluster"},
	)

	galeraFlowControlReceived = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "articdbm_galera_flow_control_received_total",
			Help: "Total number of flow control messages received by Galera node",
		},
		[]string{"node", "cluster"},
	)

	galeraCertificationFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "articdbm_galera_certification_failures_total",
			Help: "Total number of certification failures on Galera node",
		},
		[]string{"node", "cluster"},
	)

	galeraLocalCommits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "articdbm_galera_local_commits_total",
			Help: "Total number of local commits on Galera node",
		},
		[]string{"node", "cluster"},
	)

	galeraLocalReplays = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "articdbm_galera_local_replays_total",
			Help: "Total number of local replays on Galera node",
		},
		[]string{"node", "cluster"},
	)

	galeraNodeErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "articdbm_galera_node_errors_total",
			Help: "Total number of connection/health check errors for Galera node",
		},
		[]string{"node", "cluster"},
	)

	galeraReplicationLatency = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_galera_replication_latency_seconds",
			Help: "Replication latency in seconds for Galera node",
		},
		[]string{"node", "cluster"},
	)

	galeraNodeWeight = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_galera_node_weight",
			Help: "Current weight of Galera node for load balancing",
		},
		[]string{"node", "cluster"},
	)

	galeraHealthCheckDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "articdbm_galera_health_check_duration_seconds",
			Help:    "Duration of Galera node health checks",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"node", "cluster"},
	)

	// Cluster-wide metrics
	galeraClusterHealthy = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_galera_cluster_healthy",
			Help: "Whether Galera cluster is healthy (has at least one synced node)",
		},
		[]string{"cluster"},
	)

	galeraClusterSyncedNodes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_galera_cluster_synced_nodes",
			Help: "Number of synced nodes in Galera cluster",
		},
		[]string{"cluster"},
	)

	galeraClusterReadableNodes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_galera_cluster_readable_nodes",
			Help: "Number of nodes that can serve read queries in Galera cluster",
		},
		[]string{"cluster"},
	)

	galeraClusterWritableNodes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "articdbm_galera_cluster_writable_nodes",
			Help: "Number of nodes that can serve write queries in Galera cluster",
		},
		[]string{"cluster"},
	)
)

var (
	galeraMetricsMu sync.RWMutex
	galeraNodes     = make(map[string]string) // node -> cluster mapping
)

// SetGaleraNodeCluster sets the cluster name for a node
func SetGaleraNodeCluster(node, cluster string) {
	galeraMetricsMu.Lock()
	galeraNodes[node] = cluster
	galeraMetricsMu.Unlock()
}

// getClusterName returns the cluster name for a node, or "default" if not set
func getClusterName(node string) string {
	galeraMetricsMu.RLock()
	cluster, ok := galeraNodes[node]
	galeraMetricsMu.RUnlock()

	if !ok {
		return "default"
	}
	return cluster
}

// SetGaleraNodeState sets the current state of a Galera node
func SetGaleraNodeState(node string, state int) {
	cluster := getClusterName(node)
	galeraNodeState.WithLabelValues(node, cluster).Set(float64(state))
}

// SetGaleraNodeReady sets whether a Galera node is ready to serve queries
func SetGaleraNodeReady(node string, ready bool) {
	cluster := getClusterName(node)
	value := 0.0
	if ready {
		value = 1.0
	}
	galeraNodeReady.WithLabelValues(node, cluster).Set(value)
}

// SetGaleraClusterSize sets the number of nodes in the cluster
func SetGaleraClusterSize(node string, size float64) {
	cluster := getClusterName(node)
	galeraClusterSize.WithLabelValues(cluster).Set(size)
}

// SetGaleraFlowControl sets whether flow control is paused on a node
func SetGaleraFlowControl(node string, paused bool) {
	cluster := getClusterName(node)
	value := 0.0
	if paused {
		value = 1.0
	}
	galeraFlowControl.WithLabelValues(node, cluster).Set(value)
}

// IncGaleraFlowControlSent increments the flow control sent counter
func IncGaleraFlowControlSent(node string) {
	cluster := getClusterName(node)
	galeraFlowControlSent.WithLabelValues(node, cluster).Inc()
}

// IncGaleraFlowControlReceived increments the flow control received counter
func IncGaleraFlowControlReceived(node string) {
	cluster := getClusterName(node)
	galeraFlowControlReceived.WithLabelValues(node, cluster).Inc()
}

// IncGaleraCertificationFailures increments the certification failures counter
func IncGaleraCertificationFailures(node string) {
	cluster := getClusterName(node)
	galeraCertificationFailures.WithLabelValues(node, cluster).Inc()
}

// IncGaleraLocalCommits increments the local commits counter
func IncGaleraLocalCommits(node string) {
	cluster := getClusterName(node)
	galeraLocalCommits.WithLabelValues(node, cluster).Inc()
}

// IncGaleraLocalReplays increments the local replays counter
func IncGaleraLocalReplays(node string) {
	cluster := getClusterName(node)
	galeraLocalReplays.WithLabelValues(node, cluster).Inc()
}

// IncGaleraNodeErrors increments the node errors counter
func IncGaleraNodeErrors(node string) {
	cluster := getClusterName(node)
	galeraNodeErrors.WithLabelValues(node, cluster).Inc()
}

// SetGaleraReplicationLatency sets the replication latency for a node
func SetGaleraReplicationLatency(node string, latency float64) {
	cluster := getClusterName(node)
	galeraReplicationLatency.WithLabelValues(node, cluster).Set(latency)
}

// SetGaleraNodeWeight sets the current weight of a node
func SetGaleraNodeWeight(node string, weight float64) {
	cluster := getClusterName(node)
	galeraNodeWeight.WithLabelValues(node, cluster).Set(weight)
}

// ObserveGaleraHealthCheckDuration records the duration of a health check
func ObserveGaleraHealthCheckDuration(node string, duration float64) {
	cluster := getClusterName(node)
	galeraHealthCheckDuration.WithLabelValues(node, cluster).Observe(duration)
}

// SetGaleraClusterHealthy sets whether the cluster is healthy
func SetGaleraClusterHealthy(cluster string, healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	galeraClusterHealthy.WithLabelValues(cluster).Set(value)
}

// SetGaleraClusterSyncedNodes sets the number of synced nodes in the cluster
func SetGaleraClusterSyncedNodes(cluster string, count float64) {
	galeraClusterSyncedNodes.WithLabelValues(cluster).Set(count)
}

// SetGaleraClusterReadableNodes sets the number of readable nodes in the cluster
func SetGaleraClusterReadableNodes(cluster string, count float64) {
	galeraClusterReadableNodes.WithLabelValues(cluster).Set(count)
}

// SetGaleraClusterWritableNodes sets the number of writable nodes in the cluster
func SetGaleraClusterWritableNodes(cluster string, count float64) {
	galeraClusterWritableNodes.WithLabelValues(cluster).Set(count)
}