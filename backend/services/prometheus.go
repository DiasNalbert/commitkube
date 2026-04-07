package services

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

type PrometheusClient struct {
	BaseURL string
}

func NewPrometheusClient(baseURL string) *PrometheusClient {
	return &PrometheusClient{BaseURL: baseURL}
}

var promHTTPClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func (p *PrometheusClient) query(q string) (float64, error) {
	endpoint := fmt.Sprintf("%s/api/v1/query?query=%s", p.BaseURL, url.QueryEscape(q))
	resp, err := promHTTPClient.Get(endpoint)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Data struct {
			Result []struct {
				Value [2]interface{} `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, err
	}
	if len(result.Data.Result) == 0 {
		return 0, nil
	}
	raw, ok := result.Data.Result[0].Value[1].(string)
	if !ok {
		return 0, nil
	}
	return strconv.ParseFloat(raw, 64)
}

type AppMetrics struct {
	CPUCores    float64 `json:"cpu_cores"`
	MemoryBytes float64 `json:"memory_bytes"`
	NetRxBytes  float64 `json:"net_rx_bytes_per_sec"`
	NetTxBytes  float64 `json:"net_tx_bytes_per_sec"`
}

func (p *PrometheusClient) GetAppMetrics(appName, namespace string) AppMetrics {
	var podSelector string
	if namespace != "" {
		podSelector = fmt.Sprintf(`namespace="%s",pod=~"%s-.*"`, namespace, appName)
	} else {
		podSelector = fmt.Sprintf(`pod=~"%s-.*"`, appName)
	}

	cpu, _ := p.query(fmt.Sprintf(
		`sum(rate(container_cpu_usage_seconds_total{%s,container!="",container!="POD"}[5m]))`, podSelector,
	))
	mem, _ := p.query(fmt.Sprintf(
		`sum(container_memory_working_set_bytes{%s,container!="",container!="POD"})`, podSelector,
	))
	netRx, _ := p.query(fmt.Sprintf(
		`sum(rate(container_network_receive_bytes_total{%s}[5m]))`, podSelector,
	))
	netTx, _ := p.query(fmt.Sprintf(
		`sum(rate(container_network_transmit_bytes_total{%s}[5m]))`, podSelector,
	))

	return AppMetrics{
		CPUCores:    cpu,
		MemoryBytes: mem,
		NetRxBytes:  netRx,
		NetTxBytes:  netTx,
	}
}
