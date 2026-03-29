package dns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

type DNSSECKey struct {
	ZoneName     string    `json:"zone_name"`
	Algorithm    string    `json:"algorithm"`
	KeyTag       uint16    `json:"key_tag"`
	DSRecord     string    `json:"ds_record"`
	DNSKEYRecord string    `json:"dnskey_record"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
}

type DNSSECManager struct {
	keys map[string]*dnssecKeyPair
	mu   sync.RWMutex
}

type dnssecKeyPair struct {
	dnskey  *mdns.DNSKEY
	privKey crypto.Signer
	info    DNSSECKey
}

func NewDNSSECManager() *DNSSECManager {
	return &DNSSECManager{
		keys: make(map[string]*dnssecKeyPair),
	}
}

func (dm *DNSSECManager) GenerateKey(zoneName string) (*DNSSECKey, error) {
	zoneName = strings.TrimSuffix(zoneName, ".")

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	dnskey := &mdns.DNSKEY{
		Hdr: mdns.RR_Header{
			Name:   mdns.Fqdn(zoneName),
			Rrtype: mdns.TypeDNSKEY,
			Class:  mdns.ClassINET,
			Ttl:    3600,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: mdns.ECDSAP256SHA256,
	}

	// Encode public key: ECDSA P-256 = X || Y (32 bytes each, no leading 0x04)
	pubBytes := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)
	if len(pubBytes) > 0 && pubBytes[0] == 0x04 {
		pubBytes = pubBytes[1:]
	}
	dnskey.PublicKey = base64.StdEncoding.EncodeToString(pubBytes)

	keyTag := dnskey.KeyTag()
	ds := dnskey.ToDS(mdns.SHA256)

	info := DNSSECKey{
		ZoneName:     zoneName,
		Algorithm:    "ECDSAP256SHA256",
		KeyTag:       keyTag,
		DSRecord:     ds.String(),
		DNSKEYRecord: dnskey.String(),
		Enabled:      true,
		CreatedAt:    time.Now(),
	}

	dm.mu.Lock()
	dm.keys[zoneName] = &dnssecKeyPair{
		dnskey:  dnskey,
		privKey: privKey,
		info:    info,
	}
	dm.mu.Unlock()

	log.Printf("[DNSSEC] Generated key for zone '%s' (tag: %d)", zoneName, keyTag)
	return &info, nil
}

func (dm *DNSSECManager) GetKey(zoneName string) *DNSSECKey {
	zoneName = strings.TrimSuffix(zoneName, ".")
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	if kp, ok := dm.keys[zoneName]; ok {
		return &kp.info
	}
	return nil
}

func (dm *DNSSECManager) ListKeys() []DNSSECKey {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	result := make([]DNSSECKey, 0, len(dm.keys))
	for _, kp := range dm.keys {
		result = append(result, kp.info)
	}
	return result
}

func (dm *DNSSECManager) RemoveKey(zoneName string) {
	zoneName = strings.TrimSuffix(zoneName, ".")
	dm.mu.Lock()
	delete(dm.keys, zoneName)
	dm.mu.Unlock()
}

func (dm *DNSSECManager) SetEnabled(zoneName string, enabled bool) {
	zoneName = strings.TrimSuffix(zoneName, ".")
	dm.mu.Lock()
	defer dm.mu.Unlock()
	if kp, ok := dm.keys[zoneName]; ok {
		kp.info.Enabled = enabled
	}
}

func (dm *DNSSECManager) SignResponse(msg *mdns.Msg) *mdns.Msg {
	if len(msg.Answer) == 0 || len(msg.Question) == 0 {
		return msg
	}

	qname := strings.TrimSuffix(msg.Question[0].Name, ".")
	parts := strings.Split(qname, ".")

	var kp *dnssecKeyPair
	dm.mu.RLock()
	for i := 0; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")
		if k, ok := dm.keys[candidate]; ok {
			kp = k
			break
		}
	}
	dm.mu.RUnlock()

	if kp == nil || !kp.info.Enabled {
		return msg
	}

	now := time.Now().UTC()
	rrsig := &mdns.RRSIG{
		Hdr: mdns.RR_Header{
			Name:   msg.Answer[0].Header().Name,
			Rrtype: mdns.TypeRRSIG,
			Class:  mdns.ClassINET,
			Ttl:    msg.Answer[0].Header().Ttl,
		},
		TypeCovered: msg.Answer[0].Header().Rrtype,
		Algorithm:   mdns.ECDSAP256SHA256,
		Labels:      uint8(mdns.CountLabel(msg.Answer[0].Header().Name)),
		OrigTtl:     msg.Answer[0].Header().Ttl,
		Expiration:  uint32(now.Add(30 * 24 * time.Hour).Unix()),
		Inception:   uint32(now.Unix()),
		KeyTag:      kp.dnskey.KeyTag(),
		SignerName:  mdns.Fqdn(kp.info.ZoneName),
	}

	if err := rrsig.Sign(kp.privKey, msg.Answer); err != nil {
		log.Printf("[DNSSEC] Sign error: %v", err)
		return msg
	}

	msg.Answer = append(msg.Answer, rrsig)
	return msg
}
