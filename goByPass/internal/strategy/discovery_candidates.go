package strategy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// CandidateDiscoveryConfig задаёт параметры генератора и раннера discovery-кандидатов.
type CandidateDiscoveryConfig struct {
	Domains       []string
	Timeout       time.Duration
	Interval      time.Duration
	Samples       int
	MaxCandidates int
}

// CandidateProbeResult — результат одной пробы кандидата.
type CandidateProbeResult struct {
	HandshakeOK  bool          `json:"handshake_ok"`
	AppOK        bool          `json:"app_ok"`
	HandshakeRTT time.Duration `json:"handshake_rtt"`
	AppRTT       time.Duration `json:"app_rtt"`
	Error        string        `json:"error,omitempty"`
}

// CandidateDiscoveryResult агрегирует результаты кандидата по конкретному домену/протоколу.
type CandidateDiscoveryResult struct {
	StrategyID           int             `json:"strategy_id"`
	StrategyName         string          `json:"strategy_name"`
	SourceStrategyID     int             `json:"source_strategy_id"`
	Domain               string          `json:"domain"`
	Protocol             string          `json:"protocol"`
	Samples              int             `json:"samples"`
	HandshakeSuccesses   int             `json:"handshake_successes"`
	AppSuccesses         int             `json:"app_successes"`
	HandshakeSuccessRate float64         `json:"handshake_success_rate"`
	AppSuccessRate       float64         `json:"app_success_rate"`
	AvgHandshakeRTT      time.Duration   `json:"avg_handshake_rtt"`
	AvgAppRTT            time.Duration   `json:"avg_app_rtt"`
	Errors               []string        `json:"errors,omitempty"`
	Strategy             *Strategy       `json:"strategy,omitempty"`
	Probes               []CandidateProbeResult `json:"probes,omitempty"`
}

// CandidateDiscoveryReport — итоговый JSON-отчёт.
type CandidateDiscoveryReport struct {
	GeneratedAt time.Time                   `json:"generated_at"`
	Config      CandidateDiscoveryConfig    `json:"config"`
	Candidates  []*Strategy                 `json:"candidates"`
	Results     []*CandidateDiscoveryResult `json:"results"`
}

// CandidateDiscoveryRunner выполняет генерацию кандидатов и их синхронный прогон.
type CandidateDiscoveryRunner struct {
	manager *Manager
	config  CandidateDiscoveryConfig
	quicMu  sync.Mutex
}

func NewCandidateDiscoveryRunner(manager *Manager, config CandidateDiscoveryConfig) *CandidateDiscoveryRunner {
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Second
	}
	if config.Interval <= 0 {
		config.Interval = 150 * time.Millisecond
	}
	if config.Samples <= 0 {
		config.Samples = 3
	}
	if config.MaxCandidates <= 0 {
		config.MaxCandidates = 64
	}
	return &CandidateDiscoveryRunner{manager: manager, config: config}
}

// Run выполняет генерацию кандидатов, затем последовательно прогоняет их по доменам.
func (r *CandidateDiscoveryRunner) Run(ctx context.Context) (*CandidateDiscoveryReport, error) {
	candidates, err := r.GenerateCandidates(r.config.MaxCandidates)
	if err != nil {
		return nil, err
	}

	report := &CandidateDiscoveryReport{
		GeneratedAt: time.Now(),
		Config:      r.config,
		Candidates:  candidates,
		Results:     make([]*CandidateDiscoveryResult, 0, len(candidates)*len(r.config.Domains)*2),
	}

	r.manager.SetDiscoveryRunning(true)
	defer r.manager.SetDiscoveryRunning(false)

	for _, domain := range r.config.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		for _, cand := range candidates {
			select {
			case <-ctx.Done():
				return report, ctx.Err()
			default:
			}

			for _, proto := range candidateProtocols(cand) {
				result := r.runCandidateForDomain(ctx, cand, domain, proto)
				report.Results = append(report.Results, result)

				jitter := time.Duration(rand.Intn(61)) * time.Millisecond
				select {
				case <-ctx.Done():
					return report, ctx.Err()
				case <-time.After(r.config.Interval + jitter):
				}
			}
		}
	}

	sort.Slice(report.Results, func(i, j int) bool {
		a, b := report.Results[i], report.Results[j]
		if a.AppSuccessRate == b.AppSuccessRate {
			if a.HandshakeSuccessRate == b.HandshakeSuccessRate {
				if a.AvgAppRTT == b.AvgAppRTT {
					return a.AvgHandshakeRTT < b.AvgHandshakeRTT
				}
				return a.AvgAppRTT < b.AvgAppRTT
			}
			return a.HandshakeSuccessRate > b.HandshakeSuccessRate
		}
		return a.AppSuccessRate > b.AppSuccessRate
	})

	return report, nil
}

// GenerateCandidates создаёт ограниченный набор осмысленных кандидатов поверх уже существующих стратегий.
func (r *CandidateDiscoveryRunner) GenerateCandidates(limit int) ([]*Strategy, error) {
	bases := r.manager.ListStrategies()
	seen := make(map[string]struct{})
	generated := make([]*Strategy, 0, limit)
	nextID := 10000

	for _, base := range bases {
		if base == nil || isPassthrough(base) {
			continue
		}

		variants := generateCandidateVariants(base)
		for _, cand := range variants {
			if cand == nil {
				continue
			}

			fingerprint, err := candidateFingerprint(cand)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[fingerprint]; ok {
				continue
			}
			seen[fingerprint] = struct{}{}

			for {
				if _, exists := r.manager.GetStrategy(nextID); !exists {
					break
				}
				nextID++
			}

			cand.ID = nextID
			nextID++
			if cand.Priority <= 0 {
				cand.Priority = 500
			}
			if err := r.manager.AddStrategy(cand); err != nil {
				return nil, fmt.Errorf("add candidate %s: %w", cand.Name, err)
			}
			generated = append(generated, cand)
			if len(generated) >= limit {
				return generated, nil
			}
		}
	}

	return generated, nil
}

func (r *CandidateDiscoveryRunner) runCandidateForDomain(ctx context.Context, cand *Strategy, domain, proto string) *CandidateDiscoveryResult {
	result := &CandidateDiscoveryResult{
		StrategyID:       cand.ID,
		StrategyName:     cand.Name,
		Domain:           domain,
		Protocol:         proto,
		Samples:          r.config.Samples,
		Errors:           make([]string, 0, r.config.Samples),
		Probes:           make([]CandidateProbeResult, 0, r.config.Samples),
		Strategy:         cand.Clone(),
		SourceStrategyID: extractSourceStrategyID(cand.Description),
	}

	if proto == "quic" {
		r.quicMu.Lock()
		defer r.quicMu.Unlock()
	}

	r.manager.SetTestOverride(domain, cand.ID)
	defer r.manager.ClearTestOverride(domain)

	var resolvedIPs []string
	if proto == "quic" && shouldUseIPOverrideForDomain(domain) {
		if addrs, err := net.LookupHost(domain); err == nil {
			for _, addr := range addrs {
				r.manager.SetTestOverrideByIP(addr, cand.ID)
				resolvedIPs = append(resolvedIPs, addr)
			}
			defer func() {
				for _, addr := range resolvedIPs {
					r.manager.ClearTestOverrideByIP(addr)
				}
			}()
		}
	}

	for i := 0; i < r.config.Samples; i++ {
		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, ctx.Err().Error())
			return finalizeCandidateResult(result)
		default:
		}

		var probe CandidateProbeResult
		if proto == "quic" {
			probe = r.probeQUIC(ctx, domain)
		} else {
			probe = r.probeTLS(ctx, domain)
		}
		result.Probes = append(result.Probes, probe)

		if probe.HandshakeOK {
			result.HandshakeSuccesses++
			result.AvgHandshakeRTT += probe.HandshakeRTT
		}
		if probe.AppOK {
			result.AppSuccesses++
			result.AvgAppRTT += probe.AppRTT
		}
		if probe.Error != "" && len(result.Errors) < 12 {
			result.Errors = append(result.Errors, probe.Error)
		}
	}

	return finalizeCandidateResult(result)
}

func finalizeCandidateResult(result *CandidateDiscoveryResult) *CandidateDiscoveryResult {
	if result.Samples > 0 {
		result.HandshakeSuccessRate = float64(result.HandshakeSuccesses) / float64(result.Samples)
		result.AppSuccessRate = float64(result.AppSuccesses) / float64(result.Samples)
	}
	if result.HandshakeSuccesses > 0 {
		result.AvgHandshakeRTT /= time.Duration(result.HandshakeSuccesses)
	}
	if result.AppSuccesses > 0 {
		result.AvgAppRTT /= time.Duration(result.AppSuccesses)
	}
	return result
}

func (r *CandidateDiscoveryRunner) probeTLS(ctx context.Context, domain string) CandidateProbeResult {
	addr := net.JoinHostPort(domain, "443")
	dialer := &net.Dialer{Timeout: r.config.Timeout}

	handshakeStart := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, // nolint:gosec // discovery probe intentionally ignores cert validation
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		return CandidateProbeResult{Error: err.Error()}
	}
	defer conn.Close()

	probe := CandidateProbeResult{
		HandshakeOK:  true,
		HandshakeRTT: time.Since(handshakeStart),
	}

	_ = conn.SetDeadline(time.Now().Add(r.config.Timeout))
	request := "HEAD / HTTP/1.1\r\nHost: " + domain + "\r\nUser-Agent: ChainPass-Discovery/2\r\nConnection: close\r\n\r\n"

	appStart := time.Now()
	if _, err := io.WriteString(conn, request); err != nil {
		probe.Error = err.Error()
		return probe
	}

	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		probe.Error = err.Error()
		return probe
	}

	probe.AppOK = true
	probe.AppRTT = time.Since(appStart)
	return probe
}

func (r *CandidateDiscoveryRunner) probeQUIC(ctx context.Context, domain string) CandidateProbeResult {
	addr := net.JoinHostPort(domain, strconv.Itoa(443))

	handshakeCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	handshakeStart := time.Now()
	conn, err := quic.DialAddr(handshakeCtx, addr, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, // nolint:gosec // discovery probe intentionally ignores cert validation
		NextProtos:         []string{"h3", "h3-29", "h3-32", "h3-34"},
	}, &quic.Config{
		HandshakeIdleTimeout: r.config.Timeout,
		MaxIdleTimeout:       r.config.Timeout,
	})
	if err != nil {
		return CandidateProbeResult{Error: err.Error()}
	}
	probe := CandidateProbeResult{
		HandshakeOK:  true,
		HandshakeRTT: time.Since(handshakeStart),
	}
	_ = conn.CloseWithError(0, "candidate handshake probe complete")

	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         domain,
			InsecureSkipVerify: true, // nolint:gosec // discovery probe intentionally ignores cert validation
			NextProtos:         []string{"h3", "h3-29", "h3-32", "h3-34"},
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: r.config.Timeout,
			MaxIdleTimeout:       r.config.Timeout,
		},
	}
	defer transport.Close()

	client := &http.Client{Transport: transport, Timeout: r.config.Timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+domain+"/", nil)
	if err != nil {
		probe.Error = err.Error()
		return probe
	}

	appStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		probe.Error = err.Error()
		return probe
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 1)

	probe.AppOK = resp.StatusCode > 0
	probe.AppRTT = time.Since(appStart)
	if !probe.AppOK {
		probe.Error = fmt.Sprintf("unexpected status %d", resp.StatusCode)
	}
	return probe
}

func candidateProtocols(s *Strategy) []string {
	protocols := make([]string, 0, 2)
	if s.ApplyToTLS || s.ApplyToHTTP || s.AnyProtocol {
		protocols = append(protocols, "tls")
	}
	if s.ApplyToQUIC || s.FakeQUICFile != "" || len(s.FakeQUICFileData) > 0 {
		protocols = append(protocols, "quic")
	}
	if len(protocols) == 0 {
		protocols = append(protocols, "tls")
	}
	return protocols
}

func generateCandidateVariants(base *Strategy) []*Strategy {
	variants := []*Strategy{}
	push := func(s *Strategy, suffix string) {
		if s == nil {
			return
		}
		s.Name = sanitizeCandidateName(base.Name + "-" + suffix)
		s.Description = fmt.Sprintf("candidate from strategy %d (%s)", base.ID, base.Name)
		variants = append(variants, s)
	}

	push(base.Clone(), "base")

	if base.ApplyToTLS || base.ApplyToHTTP || base.AnyProtocol {
		for _, positions := range [][]int{{1}, {1, 2}, {1, 3}, {1, 5}} {
			c := base.Clone()
			if c.SplitMode == SplitNone {
				c.SplitMode = SplitCustom
			}
			c.SplitPositions = append([]int(nil), positions...)
			if c.FakedSplit {
				c.FakedSplitPos = positions[0]
			}
			push(c, fmt.Sprintf("split-%s", intsToName(positions)))
		}
	}

	if base.SeqOvlLen > 0 {
		for _, seqLen := range []int{664, 681} {
			c := base.Clone()
			c.SplitMode = SplitSeqOvl
			c.SeqOvlLen = seqLen
			if len(c.SplitPositions) == 0 {
				c.SplitPositions = []int{1}
			}
			push(c, fmt.Sprintf("seqovl-%d", seqLen))
		}
	}

	if base.FakedSplit || base.SplitMode == SplitFakedSplit {
		for _, pos := range []int{1, 2} {
			c := base.Clone()
			c.SplitMode = SplitFakedSplit
			c.FakedSplit = true
			c.FakedSplitPos = pos
			push(c, fmt.Sprintf("fakedsplit-%d", pos))
		}
	}

	if hasUsefulFakeTLS(base) {
		for _, cfg := range []struct {
			repeats int
			fooling uint32
			name    string
		}{
			{2, FoolingTS, "fake-ts-r2"},
			{4, FoolingTS, "fake-ts-r4"},
			{6, FoolingTS, "fake-ts-r6"},
			{2, FoolingBadSeq, "fake-badseq-r2"},
			{6, FoolingBadSeq, "fake-badseq-r6"},
		} {
			c := base.Clone()
			c.FakeRepeats = cfg.repeats
			c.Fooling = cfg.fooling
			if cfg.fooling == FoolingBadSeq && c.BadSeqIncrement == 0 {
				c.BadSeqIncrement = math.MaxInt32
			}
			if c.FakeTTL == 0 {
				c.FakeTTL = 6
			}
			push(c, cfg.name)
		}
	}

	if base.ApplyToQUIC || base.FakeQUICFile != "" || len(base.FakeQUICFileData) > 0 {
		for _, repeats := range []int{6, 11} {
			c := base.Clone()
			c.ApplyToQUIC = true
			c.FakeQUICRepeats = repeats
			if c.FakeTTL == 0 {
				c.FakeTTL = 6
			}
			push(c, fmt.Sprintf("quic-r%d", repeats))
		}
	}

	return variants
}

func hasUsefulFakeTLS(s *Strategy) bool {
	return len(s.FakeTLSFiles) > 0 || len(s.FakeTLSFilesData) > 0 || s.FakeTLSNullBytes || s.FakeTLSPrevPacket
}

func sanitizeCandidateName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "/", "-")
	return s
}

func intsToName(values []int) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, "-")
}

func candidateFingerprint(s *Strategy) (string, error) {
	clone := s.Clone()
	clone.ID = 0
	clone.Name = ""
	clone.Description = ""
	clone.Priority = 0
	clone.SuccessCount = 0
	clone.FailCount = 0
	clone.AvgResponseMs = 0
	clone.LastUsed = time.Time{}
	data, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func extractSourceStrategyID(description string) int {
	const prefix = "candidate from strategy "
	description = strings.ToLower(strings.TrimSpace(description))
	if !strings.HasPrefix(description, prefix) {
		return 0
	}
	rest := strings.TrimPrefix(description, prefix)
	var id int
	_, _ = fmt.Sscanf(rest, "%d", &id)
	return id
}
