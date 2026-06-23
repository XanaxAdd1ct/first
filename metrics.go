package main

import (
    "fmt"

    "github.com/prometheus/client_golang/prometheus"
)

type serverMetrics struct {
    requestsTotal *prometheus.CounterVec
    errorsTotal   *prometheus.CounterVec
    domainVersion *prometheus.GaugeVec
}

func newServerMetrics(reg prometheus.Registerer) (*serverMetrics, error) {
    m := &serverMetrics{
        requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
            Name: "coordinator_requests_total",
            Help: "Total number of requests by endpoint.",
        }, []string{"endpoint"}),

        errorsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
            Name: "coordinator_errors_total",
            Help: "Total number of errors by endpoint and status code.",
        }, []string{"endpoint", "status"}),

        domainVersion: prometheus.NewGaugeVec(prometheus.GaugeOpts{
            Name: "coordinator_domain_version",
            Help: "Current domain config version.",
        }, []string{"domain"}),
    }

    for _, c := range []prometheus.Collector{
        m.requestsTotal,
        m.errorsTotal,
        m.domainVersion,
    } {
        if err := reg.Register(c); err != nil {
            return nil, fmt.Errorf("metrics: register: %w", err)
        }
    }

    return m, nil
}