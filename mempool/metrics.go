package mempool

import (
	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/discard"
	"github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
)

const (
	// MetricsSubsystem is a subsystem shared by all metrics exposed by this
	// package.
	MetricsSubsystem = "mempool"
)

// Metrics contains metrics exposed by this package.
// see MetricsProvider for descriptions.
type Metrics struct {
	// Size of the mempool.
	Size metrics.Gauge
	// Size of mempool in bytes
	SizeBytes metrics.Gauge
	// Histogram of transaction sizes, in bytes.
	TxSizeBytes metrics.Histogram
	// Number of failed transactions.
	FailedTxs metrics.Counter
	// Number of times transactions are rechecked in the mempool.
	RecheckTimes metrics.Counter
	// Size of the max bytes reaped counter
	MaxBytesReap metrics.Gauge
	// Amount of bytes reaped
	BytesReap metrics.Gauge
	// Size of the max gas reaped counter
	MaxGasReap metrics.Gauge
	// Gas reaped
	GasReap metrics.Gauge
	// Percentage of the mempool reaped by transaction
	MempoolReapedPercent metrics.Gauge
	// Number of Txs that have arrived in the mempool
	TxsArrived metrics.Gauge
	// Number of Txs that have been verified in the mempool
	TxsVerified metrics.Gauge
}

// PrometheusMetrics returns Metrics build using Prometheus client library.
// Optionally, labels can be provided along with their values ("foo",
// "fooValue").
func PrometheusMetrics(namespace string, labelsAndValues ...string) *Metrics {
	labels := []string{}
	for i := 0; i < len(labelsAndValues); i += 2 {
		labels = append(labels, labelsAndValues[i])
	}
	return &Metrics{
		Size: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "size",
			Help:      "Size of the mempool (number of uncommitted transactions).",
		}, labels).With(labelsAndValues...),
		SizeBytes: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "size_bytes",
			Help:      "Size of the mempool in bytes",
		}, labels).With(labelsAndValues...),
		TxSizeBytes: prometheus.NewHistogramFrom(stdprometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "tx_size_bytes",
			Help:      "Transaction sizes in bytes.",
			Buckets:   stdprometheus.ExponentialBuckets(1, 3, 17),
		}, labels).With(labelsAndValues...),
		FailedTxs: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "failed_txs",
			Help:      "Number of failed transactions.",
		}, labels).With(labelsAndValues...),
		RecheckTimes: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "recheck_times",
			Help:      "Number of times transactions are rechecked in the mempool.",
		}, labels).With(labelsAndValues...),
		MaxBytesReap: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "max_bytes_reaped",
			Help:      "Amount in bytes to reap from the mempool (max)",
		}, labels).With(labelsAndValues...),
		BytesReap: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "bytes_reaped",
			Help:      "Amount in bytes reaped from the mempool",
		}, labels).With(labelsAndValues...),
		MaxGasReap: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "max_gas_reaped",
			Help:      "Amount in gas to reap from the mempool (max)",
		}, labels).With(labelsAndValues...),
		GasReap: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "gas_reaped",
			Help:      "Amount in gas reaped from the mempool",
		}, labels).With(labelsAndValues...),
		MempoolReapedPercent: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "mempool_reaped_percent",
			Help:      "Percent of the mempool reaped for block creation",
		}, labels).With(labelsAndValues...),
		TxsArrived: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "txs_arrived",
			Help:      "Number of txs that have arrived in the mempool",
		}, labels).With(labelsAndValues...),
		TxsVerified: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "txs_verified",
			Help:      "Number of txs that have been verified in the mempool",
		}, labels).With(labelsAndValues...),
	}
}

// NopMetrics returns no-op Metrics.
func NopMetrics() *Metrics {
	return &Metrics{
		Size:                 discard.NewGauge(),
		SizeBytes:            discard.NewGauge(),
		TxSizeBytes:          discard.NewHistogram(),
		FailedTxs:            discard.NewCounter(),
		RecheckTimes:         discard.NewCounter(),
		MaxBytesReap:         discard.NewGauge(),
		BytesReap:            discard.NewGauge(),
		MaxGasReap:           discard.NewGauge(),
		GasReap:              discard.NewGauge(),
		MempoolReapedPercent: discard.NewGauge(),
		TxsArrived:           discard.NewGauge(),
		TxsVerified:          discard.NewGauge(),
	}
}
