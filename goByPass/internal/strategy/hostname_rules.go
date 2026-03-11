package strategy

import (
	"log"
	"strings"
	"sync"
)

// HostnameRule описывает постоянное правило маршрутизации:
// пакеты с SNI/Host, совпадающим с Pattern, всегда обрабатываются указанной стратегией.
//
// Правила применяются в SelectStrategy ДО любой другой логики.
// Порядок проверки: exact match → wildcard suffix (*.youtube.com).
// Первое совпадение выигрывает.
type HostnameRule struct {
	// Pattern — SNI-паттерн:
	//   "www.youtube.com"  — точное совпадение
	//   "*.youtube.com"    — любой субдомен youtube.com
	//   "youtube.com"      — точное совпадение основного домена
	Pattern string `json:"pattern" yaml:"pattern"`

	// StrategyName — подстрока имени стратегии (приоритет над StrategyID).
	// Пример: "yt-discord-2026-zapret", "discord-2026", "medium".
	StrategyName string `json:"strategy" yaml:"strategy"`

	// StrategyID — ID стратегии (используется если StrategyName не задан или не найден).
	StrategyID int `json:"strategy_id,omitempty" yaml:"strategy_id,omitempty"`

	// Comment — произвольный комментарий для логов (не влияет на логику).
	Comment string `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// hostnameRules хранит скомпилированные правила для быстрого поиска.
// FIX #1: имя типа hostnameRules не конфликтует с manager.go потому что
// там переменная была переименована в builtinHostnameMappings.
type hostnameRules struct {
	mu      sync.RWMutex
	rules   []compiledRule // в порядке добавления (первое совпадение выигрывает)
	byExact map[string]int // exact hostname → strategyID (быстрый путь O(1))
}

type compiledRule struct {
	raw        HostnameRule
	strategyID int    // уже разрешённый ID стратегии
	exact      bool   // точное совпадение (hostname == pattern)
	suffix     bool   // wildcard: *.youtube.com → суффикс ".youtube.com"
	suffixPat  string // ".youtube.com" для suffix-правил
}

// SetHostnameRules загружает правила из конфига.
// Каждый вызов полностью заменяет набор правил.
//
// Стратегия для каждого правила ищется:
//  1. По StrategyName (подстрока имени) через findByName
//  2. По StrategyID если StrategyName не задан или не найден
//
// Правила с неразрешённой стратегией пропускаются с предупреждением.
func (m *Manager) SetHostnameRules(rules []HostnameRule) {
	m.hostnameRules.mu.Lock()
	defer m.hostnameRules.mu.Unlock()

	// Сбрасываем старые правила
	m.hostnameRules.rules = nil
	m.hostnameRules.byExact = make(map[string]int, len(rules))

	loaded := 0
	for _, rule := range rules {
		if rule.Pattern == "" {
			log.Printf("[HostnameRules] Skipping rule with empty pattern")
			continue
		}

		// FIX #3/#4: разрешаем стратегию через findByName (не selectByNameHint который требует protocol/port)
		// и GetStrategy которая возвращает (bool), не (error).
		sid := 0
		if rule.StrategyName != "" {
			m.mu.RLock()
			s := m.findByName(rule.StrategyName)
			m.mu.RUnlock()
			if s != nil {
				sid = s.ID
			} else {
				log.Printf("[HostnameRules] Strategy %q not found for pattern %q — trying StrategyID",
					rule.StrategyName, rule.Pattern)
			}
		}
		// FIX #3: GetStrategy возвращает (*Strategy, bool), не (*Strategy, error).
		// Было: if s, err := m.GetStrategy(sid); err == nil && s != nil
		// Стало: if s, ok := m.GetStrategy(sid); ok && s != nil
		if sid == 0 && rule.StrategyID > 0 {
			if s, ok := m.GetStrategy(rule.StrategyID); ok && s != nil {
				sid = s.ID
			}
		}
		if sid == 0 {
			log.Printf("[HostnameRules] WARNING: cannot resolve strategy for pattern %q (name=%q id=%d) — rule skipped",
				rule.Pattern, rule.StrategyName, rule.StrategyID)
			continue
		}

		cr := compiledRule{raw: rule, strategyID: sid}
		pat := strings.ToLower(rule.Pattern)

		if strings.HasPrefix(pat, "*.") {
			cr.suffix = true
			cr.suffixPat = pat[1:] // "*.youtube.com" → ".youtube.com"
		} else {
			cr.exact = true
			m.hostnameRules.byExact[pat] = sid
		}

		m.hostnameRules.rules = append(m.hostnameRules.rules, cr)

		comment := ""
		if rule.Comment != "" {
			comment = " // " + rule.Comment
		}
		log.Printf("[HostnameRules] Registered: %q → strategy %d (%s)%s",
			rule.Pattern, sid, rule.StrategyName, comment)
		loaded++
	}

	log.Printf("[HostnameRules] Loaded %d/%d rules", loaded, len(rules))
}

// hostnameRuleStrategy возвращает стратегию из статических правил для hostname.
// Возвращает nil если совпадений нет.
// Порядок: exact match (O(1)) → suffix wildcard (O(n правил)).
func (m *Manager) hostnameRuleStrategy(hostname string) *Strategy {
	if hostname == "" {
		return nil
	}
	h := strings.ToLower(strings.TrimSuffix(hostname, "."))

	m.hostnameRules.mu.RLock()
	defer m.hostnameRules.mu.RUnlock()

	// Fast path: exact match через хэш-карту
	if sid, ok := m.hostnameRules.byExact[h]; ok {
		// FIX #3: GetStrategy возвращает (bool), не (error).
		if s, ok := m.GetStrategy(sid); ok {
			return s
		}
	}

	// Slow path: wildcard suffix matching
	for _, cr := range m.hostnameRules.rules {
		if cr.exact {
			continue // уже проверено через byExact выше
		}
		if cr.suffix {
			// "*.youtube.com" → suffixPat = ".youtube.com"
			// Совпадает: sub.youtube.com, www.youtube.com
			// Совпадает: youtube.com (bare domain без ведущей точки)
			if strings.HasSuffix(h, cr.suffixPat) || h == cr.suffixPat[1:] {
				if s, ok := m.GetStrategy(cr.strategyID); ok {
					return s
				}
			}
		}
	}

	return nil
}
