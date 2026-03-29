package dns

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dachony/dns-supreme/internal/config"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type QueryResult struct {
	ClientIP       string
	ClientHostname string
	Domain         string
	QueryType      string
	Blocked        bool
	BlockRule       string
	ResponseIP     string
	Latency        time.Duration
	Timestamp      time.Time
	Upstream       string
	Protocol       string
}

type FilterFunc func(domain string, qtype uint16) (blocked bool, rule string)
type LogFunc func(result *QueryResult)

type Server struct {
	cfg        config.DNSConfig
	udpServer  *dns.Server
	tcpServer  *dns.Server
	dotServer  *dns.Server
	dohServer  *http.Server
	quicLn     *quic.Listener
	cache      *Cache
	filterFn   FilterFunc
	logFn      LogFunc
	forwarders []string
	tlsConfig  *tls.Config
	zoneLookup    ZoneLookupFunc
	zoneDataFn    ZoneDataFunc
	blockPageIP   net.IP
	onBlock       func(domain, reason string)
	hostnameCache map[string]string // IP -> hostname cache
	hostnameMu    sync.RWMutex
	mu            sync.RWMutex
}

func (s *Server) SetBlockPage(ip string, onBlock func(domain, reason string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockPageIP = net.ParseIP(ip)
	s.onBlock = onBlock
}

func NewServer(cfg config.DNSConfig, filterFn FilterFunc, logFn LogFunc, tlsCfg *tls.Config) *Server {
	return &Server{
		cfg:           cfg,
		cache:         NewCache(cfg.CacheSize),
		filterFn:      filterFn,
		logFn:         logFn,
		forwarders:    cfg.Forwarders,
		tlsConfig:     tlsCfg,
		hostnameCache: make(map[string]string),
	}
}

func (s *Server) resolveHostname(ip string) string {
	// Strip port
	host := ip
	if h, _, err := net.SplitHostPort(ip); err == nil {
		host = h
	}

	s.hostnameMu.RLock()
	cached, ok := s.hostnameCache[host]
	s.hostnameMu.RUnlock()
	if ok {
		return cached
	}

	// Async reverse lookup with timeout
	names, err := net.LookupAddr(host)
	hostname := ""
	if err == nil && len(names) > 0 {
		hostname = strings.TrimSuffix(names[0], ".")
	}

	s.hostnameMu.Lock()
	s.hostnameCache[host] = hostname
	// Limit cache size
	if len(s.hostnameCache) > 10000 {
		for k := range s.hostnameCache {
			delete(s.hostnameCache, k)
			break
		}
	}
	s.hostnameMu.Unlock()

	return hostname
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, s.cfg.Port)
	handler := dns.HandlerFunc(s.handleDNS)

	s.udpServer = &dns.Server{Addr: addr, Net: "udp", Handler: handler}
	s.tcpServer = &dns.Server{Addr: addr, Net: "tcp", Handler: handler}

	errCh := make(chan error, 4)

	go func() {
		log.Printf("[DNS] UDP listener starting on %s", addr)
		errCh <- s.udpServer.ListenAndServe()
	}()
	go func() {
		log.Printf("[DNS] TCP listener starting on %s", addr)
		errCh <- s.tcpServer.ListenAndServe()
	}()

	if s.tlsConfig != nil {
		// DoT on port 853
		dotAddr := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, 853)
		s.dotServer = &dns.Server{
			Addr:      dotAddr,
			Net:       "tcp-tls",
			TLSConfig: s.tlsConfig,
			Handler:   dns.HandlerFunc(s.handleDoT),
		}
		go func() {
			log.Printf("[DNS] DoT listener starting on %s", dotAddr)
			if err := s.dotServer.ListenAndServe(); err != nil {
				log.Printf("[DNS] DoT error: %v", err)
			}
		}()

		// DoH on port 8443 (443 reserved for block page)
		dohAddr := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, 8443)
		mux := http.NewServeMux()
		mux.HandleFunc("/dns-query", s.handleDoH)
		s.dohServer = &http.Server{
			Addr:      dohAddr,
			Handler:   mux,
			TLSConfig: s.tlsConfig.Clone(),
		}
		go func() {
			log.Printf("[DNS] DoH listener starting on %s", dohAddr)
			if err := s.dohServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Printf("[DNS] DoH error: %v", err)
			}
		}()

		// DoQ on port 8853
		go s.startDoQ()
	}

	select {
	case err := <-errCh:
		return fmt.Errorf("dns server failed: %w", err)
	case <-time.After(500 * time.Millisecond):
		log.Printf("[DNS] Server running on %s (UDP+TCP)", addr)
		if s.tlsConfig != nil {
			log.Printf("[DNS] DoT on :853, DoH on :8443, DoQ on :8853")
		}
		return nil
	}
}

func (s *Server) Shutdown() {
	if s.udpServer != nil {
		s.udpServer.Shutdown()
	}
	if s.tcpServer != nil {
		s.tcpServer.Shutdown()
	}
	if s.dotServer != nil {
		s.dotServer.Shutdown()
	}
	if s.dohServer != nil {
		s.dohServer.Close()
	}
	if s.quicLn != nil {
		s.quicLn.Close()
	}
}

// --- DoT ---

func (s *Server) handleDoT(w dns.ResponseWriter, r *dns.Msg) {
	resp := s.processDNSMsg(r, remoteAddrStr(w), "dot")
	if resp != nil {
		w.WriteMsg(resp)
	} else {
		dns.HandleFailed(w, r)
	}
}

// --- DoH (RFC 8484) ---

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	var msgBytes []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		param := r.URL.Query().Get("dns")
		if param == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		msgBytes, err = base64.RawURLEncoding.DecodeString(param)
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "invalid content type", http.StatusUnsupportedMediaType)
			return
		}
		msgBytes, err = io.ReadAll(io.LimitReader(r.Body, 65535))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil || len(msgBytes) == 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(msgBytes); err != nil {
		http.Error(w, "invalid dns message", http.StatusBadRequest)
		return
	}

	resp := s.processDNSMsg(msg, r.RemoteAddr, "doh")
	if resp == nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	respBytes, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

// --- DoQ (RFC 9250) ---

func (s *Server) startDoQ() {
	doqAddr := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, 8853)
	tlsCfg := s.tlsConfig.Clone()
	tlsCfg.NextProtos = []string{"doq"}

	ln, err := quic.ListenAddr(doqAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		log.Printf("[DNS] DoQ failed to start: %v", err)
		return
	}
	s.quicLn = ln
	log.Printf("[DNS] DoQ listener started on %s", doqAddr)

	ctx := context.Background()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		go s.handleDoQConn(ctx, conn)
	}
}

func (s *Server) handleDoQConn(ctx context.Context, conn quic.Connection) {
	defer conn.CloseWithError(0, "")
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.handleDoQStream(stream, conn.RemoteAddr().String())
	}
}

func (s *Server) handleDoQStream(stream quic.Stream, clientAddr string) {
	defer stream.Close()

	var length uint16
	if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
		return
	}
	if length == 0 || length > 65535 {
		return
	}

	msgBytes := make([]byte, length)
	if _, err := io.ReadFull(stream, msgBytes); err != nil {
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(msgBytes); err != nil {
		return
	}

	resp := s.processDNSMsg(msg, clientAddr, "doq")
	if resp == nil {
		return
	}

	respBytes, err := resp.Pack()
	if err != nil {
		return
	}

	binary.Write(stream, binary.BigEndian, uint16(len(respBytes)))
	stream.Write(respBytes)
}

// --- Core processing ---

func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	// Handle AXFR requests
	if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeAXFR {
		s.handleAXFR(w, r)
		return
	}

	resp := s.processDNSMsg(r, remoteAddrStr(w), "udp/tcp")
	if resp != nil {
		w.WriteMsg(resp)
	} else {
		dns.HandleFailed(w, r)
	}
}

func (s *Server) processDNSMsg(r *dns.Msg, clientAddr string, protocol string) *dns.Msg {
	start := time.Now()

	if len(r.Question) == 0 {
		return nil
	}

	q := r.Question[0]
	domain := q.Name
	qtype := q.Qtype

	result := &QueryResult{
		ClientIP:       clientAddr,
		ClientHostname: s.resolveHostname(clientAddr),
		Domain:         domain,
		QueryType:      dns.TypeToString[qtype],
		Timestamp:      start,
		Protocol:       protocol,
	}

	// Filter check
	if s.filterFn != nil {
		blocked, rule := s.filterFn(domain, qtype)
		if blocked {
			result.Blocked = true
			result.BlockRule = rule
			result.Latency = time.Since(start)

			msg := new(dns.Msg)
			msg.SetReply(r)

			s.mu.RLock()
			bpIP := s.blockPageIP
			onBlock := s.onBlock
			s.mu.RUnlock()

			if bpIP != nil && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
				// Return block page IP instead of NXDOMAIN
				if qtype == dns.TypeA && bpIP.To4() != nil {
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   bpIP.To4(),
					})
				}
				result.ResponseIP = bpIP.String()
				if onBlock != nil {
					onBlock(domain, rule)
				}
			} else {
				msg.Rcode = dns.RcodeNameError
			}

			if s.logFn != nil {
				s.logFn(result)
			}
			return msg
		}
	}

	// Zone lookup (authoritative)
	if zoneResp := s.resolveFromZones(domain, qtype); zoneResp != nil {
		zoneResp.SetReply(r)
		zoneResp.Authoritative = true
		result.Latency = time.Since(start)
		result.Upstream = "zone"
		if s.logFn != nil {
			s.logFn(result)
		}
		if len(zoneResp.Answer) > 0 {
			result.ResponseIP = extractIP(zoneResp.Answer[0])
		}
		return zoneResp
	}

	// Cache check
	cacheKey := fmt.Sprintf("%s-%d", domain, qtype)
	if cached, ok := s.cache.Get(cacheKey); ok {
		msg := cached.Copy()
		msg.Id = r.Id
		result.Latency = time.Since(start)
		result.Upstream = "cache"
		if s.logFn != nil {
			s.logFn(result)
		}
		return msg
	}

	// Forward
	resp, upstream, err := s.forward(r)
	if err != nil {
		log.Printf("[DNS] Forward error for %s: %v", domain, err)
		return nil
	}

	result.Upstream = upstream
	result.Latency = time.Since(start)
	if len(resp.Answer) > 0 {
		result.ResponseIP = extractIP(resp.Answer[0])
	}

	if resp.Rcode == dns.RcodeSuccess {
		if ttl := extractMinTTL(resp); ttl > 0 {
			s.cache.Set(cacheKey, resp, ttl)
		}
	}

	if s.logFn != nil {
		s.logFn(result)
	}
	return resp
}

func remoteAddrStr(w dns.ResponseWriter) string {
	if addr := w.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return ""
}

func (s *Server) GetForwarders() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, len(s.forwarders))
	copy(result, s.forwarders)
	return result
}

func (s *Server) SetForwarders(fwds []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forwarders = fwds
}

func (s *Server) forward(r *dns.Msg) (*dns.Msg, string, error) {
	s.mu.RLock()
	forwarders := s.forwarders
	s.mu.RUnlock()

	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	for _, fw := range forwarders {
		resp, _, err := c.Exchange(r, fw)
		if err == nil && resp != nil {
			return resp, fw, nil
		}
	}
	return nil, "", fmt.Errorf("all forwarders failed")
}

func extractIP(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	default:
		return ""
	}
}

func extractMinTTL(msg *dns.Msg) time.Duration {
	minTTL := uint32(300)
	for _, rr := range msg.Answer {
		if ttl := rr.Header().Ttl; ttl < minTTL {
			minTTL = ttl
		}
	}
	if minTTL < 10 {
		minTTL = 10
	}
	return time.Duration(minTTL) * time.Second
}
