// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package domainmatcher

import (
	"sort"
	"strings"

	"masterdnsvpn-go/internal/dnsparser"
	"masterdnsvpn-go/internal/enums"
)

type Action uint8

const (
	ActionFormatError Action = iota
	ActionNoData
	ActionProcess
)

type Decision struct {
	Action       Action
	Reason       string
	Question     dnsparser.Question
	RequestName  string
	BaseDomain   string
	Labels       string
	QuestionType uint16
}

type Matcher struct {
	allowedDomains []string
	minLabelLength int
}

func New(domains []string, minLabelLength int) *Matcher {
	normalized := normalizeDomains(domains)
	if minLabelLength < 1 {
		minLabelLength = 3
	}

	return &Matcher{
		allowedDomains: normalized,
		minLabelLength: minLabelLength,
	}
}

func (m *Matcher) Domains() []string {
	if len(m.allowedDomains) == 0 {
		return nil
	}

	domains := make([]string, len(m.allowedDomains))
	copy(domains, m.allowedDomains)
	return domains
}

func (m *Matcher) Match(parsed dnsparser.LitePacket) Decision {
	if len(parsed.Questions) == 0 {
		return Decision{Action: ActionFormatError, Reason: "missing-question"}
	}

	q0 := parsed.Questions[0]
	requestName := normalizeDomain(q0.Name)
	if requestName == "" || requestName == "." {
		return Decision{Action: ActionFormatError, Reason: "empty-qname"}
	}

	baseDomain, labels, matched := findAllowedDomain(requestName, m.allowedDomains)
	if !matched {
		return Decision{
			Action:       ActionNoData,
			Reason:       "unauthorized-domain",
			Question:     q0,
			RequestName:  requestName,
			QuestionType: q0.Type,
		}
	}

	if q0.Type != enums.DNSRecordTypeTXT {
		return Decision{
			Action:       ActionNoData,
			Reason:       "unsupported-qtype",
			Question:     q0,
			RequestName:  requestName,
			BaseDomain:   baseDomain,
			QuestionType: q0.Type,
		}
	}

	if labels == "" {
		return Decision{
			Action:       ActionNoData,
			Reason:       "missing-vpn-labels",
			Question:     q0,
			RequestName:  requestName,
			BaseDomain:   baseDomain,
			QuestionType: q0.Type,
		}
	}

	if len(labels) < m.minLabelLength {
		return Decision{
			Action:       ActionNoData,
			Reason:       "labels-too-short",
			Question:     q0,
			RequestName:  requestName,
			BaseDomain:   baseDomain,
			Labels:       labels,
			QuestionType: q0.Type,
		}
	}

	return Decision{
		Action:       ActionProcess,
		Reason:       "matched-vpn-domain",
		Question:     q0,
		RequestName:  requestName,
		BaseDomain:   baseDomain,
		Labels:       labels,
		QuestionType: q0.Type,
	}
}

func normalizeDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}

	unique := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		normalized := normalizeDomain(domain)
		if normalized == "" || normalized == "." {
			continue
		}
		unique[normalized] = struct{}{}
	}

	if len(unique) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(unique))
	for domain := range unique {
		normalized = append(normalized, domain)
	}

	sort.Slice(normalized, func(i, j int) bool {
		if len(normalized[i]) == len(normalized[j]) {
			return normalized[i] < normalized[j]
		}
		return len(normalized[i]) > len(normalized[j])
	})

	return normalized
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func findAllowedDomain(requestName string, allowedDomains []string) (baseDomain string, labels string, matched bool) {
	for _, domain := range allowedDomains {
		if requestName == domain {
			return domain, "", true
		}

		if len(requestName) <= len(domain)+1 {
			continue
		}

		suffix := "." + domain
		if strings.HasSuffix(requestName, suffix) {
			return domain, requestName[:len(requestName)-len(suffix)], true
		}
	}

	return "", "", false
}
