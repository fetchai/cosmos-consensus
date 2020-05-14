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
	// Number of DKG messages seen in the chain
	DKGMessagesInChain metrics.Counter
	// Number of completed DKGs
	DKGsCompleted metrics.Counter
	// DKG state gauge
	DKGState metrics.Gauge
	// Number of completed DKGs with private key for entropy generation
	DKGsCompletedWithPrivateKey metrics.Counter
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
		AvgEntropyGenTime: prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "avg_entropy_gen_time",
			Help:      "Average time in ms for entropy to be generated once the node decides to generate it",
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
		DKGsCompletedWithPrivateKey: prometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: MetricsSubsystem,
			Name:      "dkgs_completed_with_private_key",
			Help:      "Number of DKG completed with entropy generation key",
		}, labels).With(labelsAndValues...),
	}
}

// NopMetrics returns no-op Metrics.
func NopMetrics() *Metrics {
	return &Metrics{
		AvgEntropyGenTime:           discard.NewGauge(),
		DKGMessagesInChain:          discard.NewCounter(),
		DKGsCompleted:               discard.NewCounter(),
		DKGState:                    discard.NewGauge(),
		DKGsCompletedWithPrivateKey: discard.NewCounter(),
	}
}
