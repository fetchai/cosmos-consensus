package beacon

import (
	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/discard"
	"github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
)

const (
	// MetricsSubsystem is a subsystem shared by all metrics exposed by this
	// package.
	MetricsSubsystem = "beacon"
)

// Metrics contains metrics exposed by this package.
// see MetricsProvider for descriptions.
type Metrics struct {
	// Average time for entropy generation
	AvgEntropyGenTime metrics.Gauge
	// Last generated entropy height
	LastGenEntropyHeight metrics.Gauge
	// Last notified entropy height
	LastNotifyEntropyHeight metrics.Gauge
	// Have new entropy pending
	HaveNewEntropy metrics.Gauge
	// Number of DKG messages seen in the chain
	DKGMessagesInChain metrics.Counter
	// Number of completed DKGs
	DKGsCompleted metrics.Counter
	// DKG state gauge
	DKGState metrics.Gauge
	// Number of DKG failures
	DKGFailures metrics.Counter
	// Whether block round contains entropy or not
	EntropyGenerating metrics.Gauge
	// Number of drops to no entropy
	PeriodsWithNoEntropy metrics.Counter
	// Start of current aeon
	AeonStart metrics.Gauge
	// End of current aeon
	AeonEnd metrics.Gauge
	// Start of next aeon
	NextAeonStart metrics.Gauge
	// End of next aeon
	NextAeonEnd metrics.Gauge
	// Time between key arrival and aeon start
	AeonKeyBuffer metrics.Gauge
	// The ID of the current DKG
	DKGId                      metrics.Gauge
	// The iteration of the current DKG
	DKGIteration                  metrics.Gauge
	// On successful completion, the members in qual
	DKGMembersInQual              metrics.Gauge
	// Number of completed DKGs with private key for entropy generation
	DKGsCompletedWithPrivateKey metrics.Counter
	// DKG state duration in blocks
	DKGDuration metrics.Gauge
}

// PrometheusMetrics returns Metrics build using Prometheus client library.
// Optionally, labels can be provided along with their values ("foo",
// "fooValue").
func PrometheusMetrics(namespace string, labelsAndValues ...string) *Metrics {
	labels := []string{}
	for i := 0; i < len(labelsAndValues); i += 2 {
		labels = append(labels, labelsAndValues[i])
	}
	metrics := Metrics{
		AvgEntropyGenTime: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "avg_entropy_gen_time",
			Help:      "Average time in ms for entropy to be generated once the node decides to generate it",
		}, labels).With(labelsAndValues...),
		LastGenEntropyHeight: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "last_gen_entropy_height",
			Help:      "Last height entropy was generated at",
		}, labels).With(labelsAndValues...),
		LastNotifyEntropyHeight: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "last_notified_entropy_height",
			Help:      "Last height we notified the network we are at",
		}, labels).With(labelsAndValues...),
		HaveNewEntropy: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "have_new_entropy",
			Help:      "have new entropy pending",
		}, labels).With(labelsAndValues...),
		DKGMessagesInChain: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "dkg_messages_in_chain",
			Help:      "Number of DKG messages seen in the chain.",
		}, labels).With(labelsAndValues...),
		DKGsCompleted: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "dkgs_completed",
			Help:      "Number of DKG completed.",
		}, labels).With(labelsAndValues...),
		DKGState: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "dkg_state",
			Help:      "State the current DKG is at",
		}, labels).With(labelsAndValues...),
		DKGId: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "dkg_id",
			Help:      "The current dkg id",
		}, labels).With(labelsAndValues...),
		DKGIteration: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "dkg_iteratoin",
			Help:      "The current dkg id",
		}, labels).With(labelsAndValues...),
		DKGMembersInQual: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "dkg_members_in_qual",
			Help:      "The size of qual after dkg",
		}, labels).With(labelsAndValues...),
		DKGsCompletedWithPrivateKey: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "dkgs_completed_with_private_key",
			Help:      "Number of DKG completed with entropy generation key",
		}, labels).With(labelsAndValues...),
		DKGDuration: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "dkg_duration",
			Help:      "Sum of each successful dkg duration",
		}, labels).With(labelsAndValues...),
		DKGFailures: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "dkg_failures",
			Help:      "Number of DKGs failed",
		}, labels).With(labelsAndValues...),
		EntropyGenerating: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "generating_entropy",
			Help:      "Whether block contains entropy or not",
		}, labels).With(labelsAndValues...),
		PeriodsWithNoEntropy: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "periods_with_no_entropy",
			Help:      "Number of transitions to no entropy",
		}, labels).With(labelsAndValues...),
		AeonStart: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "aeon_start",
			Help:      "Start block of the loaded aeon",
		}, labels).With(labelsAndValues...),
		AeonEnd: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "aeon_end",
			Help:      "End block of the loaded aeon",
		}, labels).With(labelsAndValues...),
		NextAeonStart: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "next_aeon_start",
			Help:      "Next start block of the loaded aeon",
		}, labels).With(labelsAndValues...),
		NextAeonEnd: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "next_aeon_end",
			Help:      "Next end block of the loaded aeon",
		}, labels).With(labelsAndValues...),
		AeonKeyBuffer: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "aeon_key_buffer",
			Help:      "Time between key arrival and aeon start",
		}, labels).With(labelsAndValues...),
	}

	// Set default values for the metrics so they appear at /metrics
	// immediately, which makes testing easier
	metrics.AvgEntropyGenTime.Add(0)
	metrics.LastGenEntropyHeight.Add(0)
	metrics.LastNotifyEntropyHeight.Add(0)
	metrics.HaveNewEntropy.Add(0)
	metrics.DKGMessagesInChain.Add(0)
	metrics.DKGsCompleted.Add(0)
	metrics.DKGState.Add(0)
	metrics.DKGsCompletedWithPrivateKey.Add(0)
	metrics.DKGDuration.Add(0)
	metrics.DKGFailures.Add(0)
	metrics.EntropyGenerating.Add(0)
	metrics.PeriodsWithNoEntropy.Add(0)
	metrics.AeonStart.Add(0)
	metrics.AeonEnd.Add(0)
	metrics.NextAeonStart.Add(0)
	metrics.NextAeonEnd.Add(0)
	metrics.AeonKeyBuffer.Add(0)
	metrics.DKGId.Add(0)
	metrics.DKGMembersInQual.Add(0)
	metrics.DKGIteration.Add(0)

	return &metrics
}

// NopMetrics returns no-op Metrics.
func NopMetrics() *Metrics {
	return &Metrics{
		AvgEntropyGenTime:           discard.NewGauge(),
		LastGenEntropyHeight:        discard.NewGauge(),
		LastNotifyEntropyHeight:     discard.NewGauge(),
		HaveNewEntropy:              discard.NewGauge(),
		DKGMessagesInChain:          discard.NewCounter(),
		DKGsCompleted:               discard.NewCounter(),
		DKGState:                    discard.NewGauge(),
		DKGsCompletedWithPrivateKey: discard.NewCounter(),
		DKGDuration:                 discard.NewGauge(),
		DKGFailures:                 discard.NewCounter(),
		EntropyGenerating:           discard.NewGauge(),
		PeriodsWithNoEntropy:        discard.NewCounter(),
		AeonStart:                   discard.NewGauge(),
		AeonEnd:                     discard.NewGauge(),
		NextAeonStart:               discard.NewGauge(),
		NextAeonEnd:                 discard.NewGauge(),
		AeonKeyBuffer:               discard.NewGauge(),
		DKGId:                       discard.NewGauge(),
		DKGMembersInQual:            discard.NewGauge(),
		DKGIteration:                discard.NewGauge(),
	}
}
