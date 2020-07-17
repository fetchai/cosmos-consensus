package consensus

import (
	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/discard"

	prometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
)

const (
	// MetricsSubsystem is a subsystem shared by all metrics exposed by this
	// package.
	MetricsSubsystem = "consensus"
)

// Metrics contains metrics exposed by this package.
type Metrics struct {
	// Height of the chain.
	Height metrics.Gauge

	// ValidatorLastSignedHeight of a validator.
	ValidatorLastSignedHeight metrics.Gauge

	// Number of rounds.
	Rounds metrics.Gauge

	// Number of messages processed.
	MessagesProcessed metrics.Gauge

	// Number of validators.
	Validators metrics.Gauge
	// Total power of all validators.
	ValidatorsPower metrics.Gauge
	// Power of a validator.
	ValidatorPower metrics.Gauge
	// Amount of blocks missed by a validator.
	ValidatorMissedBlocks metrics.Gauge
	// Number of validators who did not sign.
	MissingValidators metrics.Gauge
	// Total power of the missing validators.
	MissingValidatorsPower metrics.Gauge
	// Number of validators who tried to double sign.
	ByzantineValidators metrics.Gauge
	// Total power of the byzantine validators.
	ByzantineValidatorsPower metrics.Gauge

	// Time between this and the last block.
	BlockIntervalSeconds metrics.Gauge

	// Number of transactions (and dkg).
	NumTxs    metrics.Gauge
	NumDKGTxs metrics.Gauge
	// Size of the block.
	BlockSizeBytes metrics.Gauge
	// Total number of transactions.
	TotalTxs    metrics.Gauge
	TotalDKGTxs metrics.Gauge
	// The latest block height.
	CommittedHeight metrics.Gauge
	// Whether or not a node is fast syncing. 1 if yes, 0 if no.
	FastSyncing metrics.Gauge

	// Number of blockparts transmitted by peer.
	BlockParts metrics.Counter

	// Number of times failed as block producer
	NumFailuresAsBlockProducer metrics.Counter

	// Number of times was the block producer
	NumBlockProducer metrics.Counter

	// Whether the current block has entropy, 1 if yes, 0 if no
	BlockWithEntropy metrics.Gauge
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
		Height: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "height",
			Help:      "Height of the chain.",
		}, labels).With(labelsAndValues...),
		Rounds: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "rounds",
			Help:      "Number of rounds.",
		}, labels).With(labelsAndValues...),
		MessagesProcessed: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "messages_processed",
			Help:      "Number of messages processed.",
		}, labels).With(labelsAndValues...),

		Validators: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "validators",
			Help:      "Number of validators.",
		}, labels).With(labelsAndValues...),
		ValidatorLastSignedHeight: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "validator_last_signed_height",
			Help:      "Last signed height for a validator",
		}, append(labels, "validator_address")).With(labelsAndValues...),
		ValidatorMissedBlocks: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "validator_missed_blocks",
			Help:      "Total missed blocks for a validator",
		}, append(labels, "validator_address")).With(labelsAndValues...),
		ValidatorsPower: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "validators_power",
			Help:      "Total power of all validators.",
		}, labels).With(labelsAndValues...),
		ValidatorPower: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "validator_power",
			Help:      "Power of a validator",
		}, append(labels, "validator_address")).With(labelsAndValues...),
		MissingValidators: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "missing_validators",
			Help:      "Number of validators who did not sign.",
		}, labels).With(labelsAndValues...),
		MissingValidatorsPower: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "missing_validators_power",
			Help:      "Total power of the missing validators.",
		}, labels).With(labelsAndValues...),
		ByzantineValidators: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "byzantine_validators",
			Help:      "Number of validators who tried to double sign.",
		}, labels).With(labelsAndValues...),
		ByzantineValidatorsPower: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "byzantine_validators_power",
			Help:      "Total power of the byzantine validators.",
		}, labels).With(labelsAndValues...),

		BlockIntervalSeconds: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "block_interval_seconds",
			Help:      "Time between this and the last block.",
		}, labels).With(labelsAndValues...),

		NumTxs: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "num_txs",
			Help:      "Number of transactions.",
		}, labels).With(labelsAndValues...),
		NumDKGTxs: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "num_dkg_txs",
			Help:      "Number of dkg transactions.",
		}, labels).With(labelsAndValues...),
		BlockSizeBytes: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "block_size_bytes",
			Help:      "Size of the block.",
		}, labels).With(labelsAndValues...),
		TotalTxs: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "total_txs",
			Help:      "Total number of transactions.",
		}, labels).With(labelsAndValues...),
		TotalDKGTxs: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "total_dkg_txs",
			Help:      "Total number of transactions.",
		}, labels).With(labelsAndValues...),
		CommittedHeight: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "latest_block_height",
			Help:      "The latest block height.",
		}, labels).With(labelsAndValues...),
		FastSyncing: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "fast_syncing",
			Help:      "Whether or not a node is fast syncing. 1 if yes, 0 if no.",
		}, labels).With(labelsAndValues...),
		BlockParts: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "block_parts",
			Help:      "Number of blockparts transmitted by peer.",
		}, append(labels, "peer_id")).With(labelsAndValues...),
		NumFailuresAsBlockProducer: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "block_producer_failures",
			Help:      "Number of times failed as block producer",
		}, labels).With(labelsAndValues...),
		NumBlockProducer: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "block_producer",
			Help:      "Number of times was the block producer",
		}, labels).With(labelsAndValues...),
		BlockWithEntropy: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "block_with_entropy",
			Help:      "Whether the current block contains entropy or not",
		}, labels).With(labelsAndValues...),
	}
}

// NopMetrics returns no-op Metrics.
func NopMetrics() *Metrics {
	return &Metrics{
		Height: discard.NewGauge(),

		ValidatorLastSignedHeight: discard.NewGauge(),

		Rounds: discard.NewGauge(),
		MessagesProcessed: discard.NewGauge(),

		Validators:               discard.NewGauge(),
		ValidatorsPower:          discard.NewGauge(),
		ValidatorPower:           discard.NewGauge(),
		ValidatorMissedBlocks:    discard.NewGauge(),
		MissingValidators:        discard.NewGauge(),
		MissingValidatorsPower:   discard.NewGauge(),
		ByzantineValidators:      discard.NewGauge(),
		ByzantineValidatorsPower: discard.NewGauge(),

		BlockIntervalSeconds: discard.NewGauge(),

		NumTxs:          discard.NewGauge(),
		NumDKGTxs:       discard.NewGauge(),
		BlockSizeBytes:  discard.NewGauge(),
		TotalTxs:        discard.NewGauge(),
		TotalDKGTxs:     discard.NewGauge(),
		CommittedHeight: discard.NewGauge(),
		FastSyncing:     discard.NewGauge(),
		BlockParts:      discard.NewCounter(),

		NumFailuresAsBlockProducer: discard.NewCounter(),
		NumBlockProducer:           discard.NewCounter(),
		BlockWithEntropy:           discard.NewGauge(),
	}
}
