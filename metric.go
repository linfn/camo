package camo

import (
	"encoding/json"
	"expvar"
	"io"
)

// MetricInt ...
type MetricInt struct {
	expvar.Int
}

// MarshalJSON ...
func (i *MetricInt) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.Value())
}

// IOMetric ...
type IOMetric struct {
	ReadBytes  *MetricInt `json:"read_bytes"`
	WriteBytes *MetricInt `json:"write_bytes"`
}

// NewIOMetric ...
func NewIOMetric() *IOMetric {
	return &IOMetric{
		ReadBytes:  new(MetricInt),
		WriteBytes: new(MetricInt),
	}
}

// TunnelMetrics ...
type TunnelMetrics struct {
	*IOMetric
	Streams *MetricInt `json:"streams"`
	Lags    *MetricInt `json:"lags"`
	Drops   *MetricInt `json:"drops"`
}

// NewTunnelMetrics ...
func NewTunnelMetrics() *TunnelMetrics {
	return &TunnelMetrics{
		IOMetric: NewIOMetric(),
		Streams:  new(MetricInt),
		Lags:     new(MetricInt),
		Drops:    new(MetricInt),
	}
}

// Metrics ...
type Metrics struct {
	Iface      *IOMetric      `json:"iface"`
	Tunnels    *TunnelMetrics `json:"tunnels"`
	BufferSize *MetricInt     `json:"buffer_size"`
}

// NewMetrics ...
func NewMetrics() *Metrics {
	return &Metrics{
		Iface:      NewIOMetric(),
		Tunnels:    NewTunnelMetrics(),
		BufferSize: new(MetricInt),
	}
}

// String returns a valid json string
func (m *Metrics) String() string {
	b, _ := json.Marshal(m)
	return string(b)
}

type ioMetricWrapper struct {
	rw     io.ReadWriteCloser
	metric *IOMetric
}

func (m *ioMetricWrapper) Read(b []byte) (int, error) {
	n, err := m.rw.Read(b)
	m.metric.ReadBytes.Add(int64(n))
	return n, err
}

func (m *ioMetricWrapper) Write(b []byte) (int, error) {
	n, err := m.rw.Write(b)
	m.metric.WriteBytes.Add(int64(n))
	return n, err
}

func (m *ioMetricWrapper) Close() error {
	return m.rw.Close()
}

// WithIOMetric ...
func WithIOMetric(rw io.ReadWriteCloser, metric *IOMetric) io.ReadWriteCloser {
	return &ioMetricWrapper{
		rw:     rw,
		metric: metric,
	}
}
