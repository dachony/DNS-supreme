package filter

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Category string

const (
	CategoryAds       Category = "ads"
	CategoryMalware   Category = "malware"
	CategoryAdult     Category = "adult"
	CategorySocial    Category = "social"
	CategoryGambling  Category = "gambling"
	CategoryTracking  Category = "tracking"
	CategoryCustom    Category = "custom"
	CategoryUncategorized Category = "uncategorized"
)

type BlockList struct {
	Name     string   `json:"name"`
	URL      string   `json:"url"`
	Category Category `json:"category"`
	Enabled  bool     `json:"enabled"`
	Count    int      `json:"count"`
}

type domainEntry struct {
	listName string
	category Category
}

type Engine struct {
	domains            map[string]domainEntry // domain -> entry
	allowlist          map[string]bool
	customList         map[string]string      // domain -> reason
	lists              []BlockList
	disabledCategories map[Category]bool
	geoBlockedCountries map[string]bool       // country code -> blocked
	geoLookup          GeoLookupFunc
	mode               string                // "blocklist" or "allowlist"
	mu                 sync.RWMutex
}

// GeoLookupFunc resolves an IP to a country code
type GeoLookupFunc func(ip string) string

func NewEngine() *Engine {
	return &Engine{
		domains:            make(map[string]domainEntry),
		allowlist:          make(map[string]bool),
		customList:         make(map[string]string),
		lists:              make([]BlockList, 0),
		disabledCategories: make(map[Category]bool),
		geoBlockedCountries: make(map[string]bool),
		mode:               "blocklist",
	}
}

func (e *Engine) GetMode() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mode
}

func (e *Engine) SetMode(mode string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mode = mode
}

func (e *Engine) SetGeoLookup(fn GeoLookupFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.geoLookup = fn
}

func (e *Engine) Check(domain string, qtype uint16) (blocked bool, rule string) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	e.mu.RLock()
	defer e.mu.RUnlock()

	// Allowlist mode: block everything EXCEPT allowed domains
	if e.mode == "allowlist" {
		if e.allowlist[domain] {
			return false, ""
		}
		// Check parent domains for allowlist
		parts := strings.Split(domain, ".")
		for i := 1; i < len(parts)-1; i++ {
			if e.allowlist[strings.Join(parts[i:], ".")] {
				return false, ""
			}
		}
		return true, "allowlist mode: domain not on allowlist"
	}

	// Blocklist mode (default): allow everything EXCEPT blocked domains

	// Allowlist takes priority
	if e.allowlist[domain] {
		return false, ""
	}

	// Custom blocklist
	if reason, ok := e.customList[domain]; ok {
		return true, "custom: " + reason
	}

	// Blocklists — exact and parent domain match
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		checkDomain := strings.Join(parts[i:], ".")
		if entry, ok := e.domains[checkDomain]; ok {
			if e.disabledCategories[entry.category] {
				continue
			}
			return true, fmt.Sprintf("[%s] %s", entry.category, entry.listName)
		}
	}

	return false, ""
}

// CheckGeo checks if a client IP should be blocked by geo policy
func (e *Engine) CheckGeo(clientIP string) (blocked bool, country string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.geoLookup == nil || len(e.geoBlockedCountries) == 0 {
		return false, ""
	}

	cc := e.geoLookup(clientIP)
	if cc == "" {
		return false, ""
	}
	if e.geoBlockedCountries[cc] {
		return true, cc
	}
	return false, cc
}

// --- Category management ---

func (e *Engine) EnableCategory(cat Category) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.disabledCategories, cat)
}

func (e *Engine) DisableCategory(cat Category) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disabledCategories[cat] = true
}

func (e *Engine) GetCategories() map[Category]bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := map[Category]bool{
		CategoryAds:      true,
		CategoryMalware:  true,
		CategoryAdult:    true,
		CategorySocial:   true,
		CategoryGambling: true,
		CategoryTracking: true,
	}
	for cat := range e.disabledCategories {
		result[cat] = false
	}
	return result
}

// --- Geo management ---

func (e *Engine) SetGeoBlocked(countryCodes []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.geoBlockedCountries = make(map[string]bool)
	for _, cc := range countryCodes {
		e.geoBlockedCountries[strings.ToUpper(cc)] = true
	}
}

func (e *Engine) GetGeoBlocked() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]string, 0, len(e.geoBlockedCountries))
	for cc := range e.geoBlockedCountries {
		result = append(result, cc)
	}
	return result
}

// --- Allowlist ---

func (e *Engine) AddAllowlistDomain(domain string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.allowlist[strings.TrimSuffix(strings.ToLower(domain), ".")] = true
}

func (e *Engine) RemoveAllowlistDomain(domain string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.allowlist, strings.TrimSuffix(strings.ToLower(domain), "."))
}

func (e *Engine) GetAllowlist() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	list := make([]string, 0, len(e.allowlist))
	for d := range e.allowlist {
		list = append(list, d)
	}
	return list
}

// --- Custom blocks ---

func (e *Engine) AddCustomBlock(domain, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.customList[strings.TrimSuffix(strings.ToLower(domain), ".")] = reason
}

func (e *Engine) RemoveCustomBlock(domain string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.customList, strings.TrimSuffix(strings.ToLower(domain), "."))
}

func (e *Engine) GetCustomBlocks() map[string]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string]string, len(e.customList))
	for k, v := range e.customList {
		result[k] = v
	}
	return result
}

// --- Blocklist management ---

func (e *Engine) GetLists() []BlockList {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]BlockList, len(e.lists))
	copy(result, e.lists)
	return result
}

// GetListDomains returns a sample of domains from a specific list (max 200)
func (e *Engine) GetListDomains(listName string, max int) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if max <= 0 || max > 200 {
		max = 200
	}
	result := make([]string, 0, max)
	for domain, entry := range e.domains {
		if entry.listName == listName {
			result = append(result, domain)
			if len(result) >= max {
				break
			}
		}
	}
	return result
}

func (e *Engine) AddList(name, url string, category Category) error {
	if category == "" {
		category = CategoryUncategorized
	}
	count, err := e.loadFromURL(url, name, category)
	if err != nil {
		return fmt.Errorf("failed to load list %s: %w", name, err)
	}

	e.mu.Lock()
	e.lists = append(e.lists, BlockList{
		Name:     name,
		URL:      url,
		Category: category,
		Enabled:  true,
		Count:    count,
	})
	e.mu.Unlock()

	log.Printf("[Filter] Loaded list '%s' [%s] from %s (%d domains)", name, category, url, count)
	return nil
}

func (e *Engine) RemoveList(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for d, entry := range e.domains {
		if entry.listName == name {
			delete(e.domains, d)
		}
	}

	for i, l := range e.lists {
		if l.Name == name {
			e.lists = append(e.lists[:i], e.lists[i+1:]...)
			break
		}
	}
}

func (e *Engine) LoadFromFile(path, listName string, category Category) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return e.parseList(f, listName, category)
}

func (e *Engine) loadFromURL(url, listName string, category Category) (int, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return e.parseList(resp.Body, listName, category)
}

func (e *Engine) parseList(r io.Reader, listName string, category Category) (int, error) {
	scanner := bufio.NewScanner(r)
	count := 0

	e.mu.Lock()
	defer e.mu.Unlock()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		domain := ""

		// Hosts file format
		if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				domain = parts[1]
			}
		} else if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
			// AdBlock format
			domain = strings.TrimPrefix(line, "||")
			domain = strings.TrimSuffix(domain, "^")
		} else if !strings.Contains(line, " ") && strings.Contains(line, ".") {
			// Plain domain
			domain = line
		}

		if domain != "" {
			domain = strings.ToLower(domain)
			if domain != "localhost" && !strings.HasPrefix(domain, "localhost.") {
				e.domains[domain] = domainEntry{listName: listName, category: category}
				count++
			}
		}
	}

	return count, scanner.Err()
}

func (e *Engine) Stats() (total int, lists int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.domains) + len(e.customList), len(e.lists)
}

func (e *Engine) CategoryStats() map[Category]int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[Category]int)
	for _, entry := range e.domains {
		result[entry.category]++
	}
	return result
}
