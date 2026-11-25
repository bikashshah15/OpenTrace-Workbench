package main

// osv_advisory_match (I2-REQ-05): offline interpretation of captured OSV batch results and full
// advisory records. B reads only the digests listed in the bundle manifest it was given; it never
// fetches anything. Package/version matching is OSV's; B preserves its fidelity, keeps incomplete
// queries explicit, and never turns a positive or withdrawn-only result into an empty one.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"time"
)

const (
	opOSV           = "osv_advisory_match"
	maxOSVPages     = 10
	maxBundleBytes  = 16 << 20
	emptyResultText = "No advisory matches returned for the queried version in this capture."
)

func init() { registerV2(opOSV, "inventory", osvHandler) }

type osvPlanned struct {
	QueryKey   string `json:"query_key"`
	Module     string `json:"module"`
	Version    string `json:"version"`
	SkipReason string `json:"skip_reason,omitempty"`
}

type osvRound struct {
	Request  string `json:"request"`
	Response string `json:"response"`
	Status   int    `json:"status"`
}

type osvRecordRef struct {
	Digest string `json:"digest"`
	Status int    `json:"status"`
}

type osvBundle struct {
	Schema       string                  `json:"schema"`
	Kind         string                  `json:"kind"`
	CaptureSetID string                  `json:"capture_set_id"`
	Queries      []osvPlanned            `json:"queries"`
	Rounds       []osvRound              `json:"rounds"`
	Records      map[string]osvRecordRef `json:"records"`
	// keyFn, when set, derives the query key from a captured request (major 3.0 keys carry the
	// ecosystem); it is never decoded from JSON. The default is the 2.0 name@version key.
	keyFn func(osvQuery) string
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
		Purl      string `json:"purl"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token"`
}

func (q osvQuery) key() string {
	name := q.Package.Name
	if name == "" {
		name = q.Package.Purl
	}
	return name + "@" + q.Version
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

type osvQueryState struct {
	Key        string
	Module     string
	Version    string
	IDs        []string
	seen       map[string]bool
	Pages      int
	HasToken   bool
	Failed     string // reason text when a round failed or was malformed
	Seen       bool   // appeared in at least one request
	Returned   int
	Active     int
	Complete   bool
	SkipReason string
}

type osvRecord struct {
	ID         string   `json:"id"`
	Aliases    []string `json:"aliases"`
	Related    []string `json:"related"`
	Upstream   []string `json:"upstream"`
	Withdrawn  string   `json:"withdrawn"`
	Severity   []any    `json:"severity"`
	Summary    string   `json:"summary"`
	Modified   string   `json:"modified"`
	Published  string   `json:"published"`
	References []any    `json:"references"`
	Affected   []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string           `json:"type"`
			Events []map[string]any `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	// DatabaseSpecific is the recorded database_specific object; major 3.0 reads its severity label.
	DatabaseSpecific map[string]any `json:"database_specific"`
}

// osvAnalysis is the pure result of interpreting a bundle (no I/O, no task context).
type osvAnalysis struct {
	Queries []*osvQueryState
	Matches []osvMatch
	// Unavailable lists (queryKey, id) pairs whose record was missing or failed.
	Unavailable []osvUnavailable
}

type osvMatch struct {
	QueryKey, Module, Version, ID string
	Record                        *osvRecord
	RecordDigest                  string
	Withdrawn                     bool
	RangeCheck                    string
	Events                        []map[string]any
}

type osvUnavailable struct{ QueryKey, ID, Detail string }

type osvReader interface {
	Read(digest string, max int) ([]byte, error)
}

type storeReader struct{ s Store }

func (r storeReader) Read(digest string, max int) ([]byte, error) { return r.s.ReadMax(digest, max) }

// analyzeOSV interprets the bundle. It never panics on malformed input: every defect becomes an
// explicit incomplete query or unavailable record.
func analyzeOSV(b *osvBundle, rd osvReader) *osvAnalysis {
	an := &osvAnalysis{}
	states := map[string]*osvQueryState{}
	var order []string
	get := func(key string) *osvQueryState {
		if st, ok := states[key]; ok {
			return st
		}
		st := &osvQueryState{Key: key, seen: map[string]bool{}}
		states[key] = st
		order = append(order, key)
		return st
	}
	planned := map[string]bool{}
	for _, p := range b.Queries {
		planned[p.QueryKey] = true
	}
	// When the bundle names the queries to evaluate, other queries that happen to share a captured
	// request are ignored: a task for one variant never reports another variant's versions.
	filter := len(planned) > 0
	for _, p := range b.Queries {
		st := get(p.QueryKey)
		st.Module, st.Version, st.SkipReason = p.Module, p.Version, p.SkipReason
	}
	for ri, round := range b.Rounds {
		reqBody, err1 := rd.Read(round.Request, 4<<20)
		var queries struct {
			Queries []osvQuery `json:"queries"`
		}
		if err1 != nil || json.Unmarshal(reqBody, &queries) != nil {
			markUnreadable(states, b, ri, "request is missing or malformed")
			continue
		}
		keys := make([]string, len(queries.Queries))
		for i, q := range queries.Queries {
			keys[i] = q.key()
			if b.keyFn != nil {
				keys[i] = b.keyFn(q)
			}
			if filter && !planned[keys[i]] {
				continue
			}
			st := get(keys[i])
			if st.Module == "" {
				st.Module, st.Version = q.Package.Name, q.Version
			}
			st.Seen = true
			st.Failed = "" // judged again by this round's response
			st.HasToken = true
		}
		active := func(k string) bool { return !filter || planned[k] }
		if round.Status != 200 {
			for _, k := range keys {
				if !active(k) {
					continue
				}
				states[k].Failed = fmt.Sprintf("round %d returned HTTP %d", ri+1, round.Status)
			}
			continue
		}
		respBody, err2 := rd.Read(round.Response, maxBundleBytes)
		var resp osvBatchResponse
		if err2 != nil || json.Unmarshal(respBody, &resp) != nil {
			for _, k := range keys {
				if active(k) {
					states[k].Failed = fmt.Sprintf("round %d response is missing or malformed", ri+1)
				}
			}
			continue
		}
		if len(resp.Results) != len(keys) {
			for _, k := range keys {
				if active(k) {
					states[k].Failed = fmt.Sprintf("round %d returned %d results for %d queries", ri+1, len(resp.Results), len(keys))
				}
			}
			continue
		}
		for i, k := range keys {
			if !active(k) {
				continue
			}
			st := states[k]
			st.Pages++
			for _, v := range resp.Results[i].Vulns {
				if v.ID != "" && !st.seen[v.ID] {
					st.seen[v.ID] = true
					st.IDs = append(st.IDs, v.ID)
				}
			}
			st.HasToken = resp.Results[i].NextPageToken != ""
		}
	}
	for _, key := range order {
		st := states[key]
		switch {
		case st.SkipReason != "":
			st.Complete = false
		case !st.Seen:
			st.Failed = "query does not appear in the captured requests"
		case st.Pages > maxOSVPages:
			st.Failed = fmt.Sprintf("more than %d pages", maxOSVPages)
		case st.HasToken && st.Failed == "":
			st.Failed = "next_page_token remained after the last captured round"
		}
		st.Complete = st.SkipReason == "" && st.Failed == ""
		an.Queries = append(an.Queries, st)
	}
	for _, st := range an.Queries {
		if st.SkipReason != "" {
			continue
		}
		for _, id := range st.IDs {
			ref, ok := b.Records[id]
			var rec osvRecord
			data, err := []byte(nil), errors.New("no record")
			if ok && ref.Status == 200 {
				data, err = rd.Read(ref.Digest, 4<<20)
			} else if ok {
				err = fmt.Errorf("record fetch returned HTTP %d", ref.Status)
			}
			if err == nil && (json.Unmarshal(data, &rec) != nil || rec.ID != id) {
				err = errors.New("record is malformed or names another ID")
			}
			if err != nil {
				an.Unavailable = append(an.Unavailable, osvUnavailable{QueryKey: st.Key, ID: id, Detail: err.Error()})
				continue
			}
			st.Returned++
			m := osvMatch{QueryKey: st.Key, Module: st.Module, Version: st.Version, ID: id, Record: &rec,
				RecordDigest: ref.Digest, Withdrawn: rec.Withdrawn != ""}
			if !m.Withdrawn {
				st.Active++
			}
			m.RangeCheck, m.Events = rangeCheck(&rec, st.Module, st.Version)
			an.Matches = append(an.Matches, m)
		}
		// Records that could not be loaded still count as returned IDs: the query was not empty.
		for _, u := range an.Unavailable {
			if u.QueryKey == st.Key {
				st.Returned++
			}
		}
	}
	return an
}

// markUnreadable is conservative: when a round's request cannot be read its queries are unknown,
// so every query that was not already fully resolved becomes incomplete.
func markUnreadable(states map[string]*osvQueryState, b *osvBundle, round int, why string) {
	for _, st := range states {
		if !st.Seen || st.HasToken {
			st.Failed = fmt.Sprintf("round %d: %s", round+1, why)
		}
	}
}

// ---- semver range check (plain vMAJOR.MINOR.PATCH only) ------------------------------------

var plainSemver = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

type sv [3]int

func parseSV(s string) (sv, bool) {
	if s == "0" {
		return sv{}, true
	}
	m := plainSemver.FindStringSubmatch(s)
	if m == nil {
		return sv{}, false
	}
	var out sv
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return sv{}, false
		}
		out[i] = n
	}
	return out, true
}

func (a sv) less(b sv) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// rangeCheck evaluates the recorded introduced/fixed/last_affected events for the queried module
// against the queried version. Anything that is not plain semver is not_evaluated, never guessed.
func rangeCheck(rec *osvRecord, module, version string) (string, []map[string]any) {
	var events []map[string]any
	target, ok := parseSV(version)
	evaluated, affected := ok, false
	found := false
	for _, a := range rec.Affected {
		if a.Package.Name != module {
			continue
		}
		for _, r := range a.Ranges {
			events = append(events, r.Events...)
			if r.Type != "SEMVER" {
				evaluated = false
				continue
			}
			found = true
			var intro *sv
			closeAt := func(end sv, inclusive bool) {
				if intro != nil && !target.less(*intro) && (target.less(end) || (inclusive && target == end)) {
					affected = true
				}
				intro = nil
			}
			for _, ev := range r.Events {
				switch {
				case ev["introduced"] != nil:
					v, ok := parseSV(fmt.Sprint(ev["introduced"]))
					if !ok {
						evaluated = false
					}
					intro = &v
				case ev["fixed"] != nil:
					v, ok := parseSV(fmt.Sprint(ev["fixed"]))
					if !ok {
						evaluated = false
					}
					closeAt(v, false)
				case ev["last_affected"] != nil:
					v, ok := parseSV(fmt.Sprint(ev["last_affected"]))
					if !ok {
						evaluated = false
					}
					closeAt(v, true)
				}
			}
			if intro != nil && !target.less(*intro) {
				affected = true // open interval
			}
		}
	}
	if events == nil {
		events = []map[string]any{}
	}
	switch {
	case !found || !evaluated:
		return "not_evaluated", events
	case affected:
		return "consistent", events
	default:
		return "inconsistent", events
	}
}

// ---- the operation ---------------------------------------------------------------------------

type osvStoreReader struct{ s Store }

func (r osvStoreReader) Read(digest string, max int) ([]byte, error) { return r.s.ReadMax(digest, max) }

func osvHandler(s *Server, ctx context.Context, t *TaskRequest, input *ArtifactRef, jobDeadline time.Time, tokens []Part) *Message {
	res := s.newV2Result(t, opOSV)
	unsupportedRequirements(res, t, opOSV, "inventory")
	rej := func(code, msg string) *Message {
		return s.rejectV2(tokens, false, code, msg, t.TaskID, t.RunID)
	}
	if *t.Budget.MaxWorkerJobs < 1 {
		return s.failV2(res, t, tokens, "budget_exhausted", "The task budget allows no worker job.")
	}
	ref := inputByRole(t, "osv_bundle_manifest")
	if ref == nil {
		return rej("invalid_request", "An osv_bundle_manifest input is required.")
	}
	raw, err := s.store.ReadMax(ref.Digest, maxBundleBytes)
	if err != nil {
		code := "artifact_not_found"
		if errors.Is(err, errIntegrity) {
			code = "artifact_integrity_failure"
		}
		return s.failV2(res, t, tokens, code, "The bundle manifest could not be read from the store.")
	}
	var bundle osvBundle
	if json.Unmarshal(raw, &bundle) != nil || bundle.Kind != "osv" {
		return s.failV2(res, t, tokens, "artifact_integrity_failure", "The bundle manifest is not an osv bundle.")
	}
	if bundle.CaptureSetID != t.CaptureSetID {
		return rej("capture_mismatch", "The bundle's capture_set_id differs from the task's.")
	}
	if ctx.Err() != nil || time.Now().After(jobDeadline) {
		return s.failV2(res, t, tokens, "worker_timeout", "The task deadline passed before analysis.")
	}
	an := analyzeOSV(&bundle, osvStoreReader{s.store})
	stamp := s.now().Format(timeLayout)
	req := firstRequirement(t, "inventory")
	method := func(out string) CollectionMethod {
		return CollectionMethod{Tool: "osv_advisory_match", ToolVersion: "evidence-specialist-b/i2",
			ArgvTemplate: []string{"osv_advisory_match", "<bundle-manifest>"}, OutputArtifact: out}
	}

	// Produced artifact first: evidence refers to its digest.
	type tableQuery struct {
		QueryKey string   `json:"query_key"`
		Module   string   `json:"module"`
		Version  string   `json:"version"`
		Pages    int      `json:"pages"`
		Complete bool     `json:"all_pages_complete"`
		Returned int      `json:"returned_count"`
		Active   int      `json:"active_count"`
		IDs      []string `json:"ids"`
		Skip     string   `json:"skip_reason,omitempty"`
		Failure  string   `json:"failure,omitempty"`
	}
	table := struct {
		Schema       string           `json:"schema"`
		CaptureSetID string           `json:"capture_set_id"`
		Queries      []tableQuery     `json:"queries"`
		Matches      []map[string]any `json:"matches"`
	}{Schema: "opentrace.osv_match_table/1", CaptureSetID: bundle.CaptureSetID}
	for _, q := range an.Queries {
		ids := append([]string{}, q.IDs...)
		sort.Strings(ids)
		table.Queries = append(table.Queries, tableQuery{q.Key, q.Module, q.Version, q.Pages, q.Complete, q.Returned, q.Active, ids, q.SkipReason, q.Failed})
	}
	table.Matches = []map[string]any{}
	for _, m := range an.Matches {
		table.Matches = append(table.Matches, map[string]any{"query_key": m.QueryKey, "vuln_id": m.ID,
			"withdrawn": m.Withdrawn, "range_check": m.RangeCheck, "record_artifact": m.RecordDigest})
	}
	tableDigest, err := s.addProduced(res, t, canonicalJSON(table), "application/json", "match_table",
		serviceID+"/"+opOSV, ref.Digest)
	if err != nil {
		return s.failV2(res, t, tokens, "output_too_large", "The match table exceeds the artifact budget.")
	}

	subject := func(q *osvQueryState) Subject { return Subject{Module: q.Module, Version: q.Version, Indirect: false} }
	bundleRef := ArtifactRef{Digest: ref.Digest, MediaType: ref.MediaType, Role: "osv_bundle_manifest"}
	activeSeen := 0
	for i, m := range an.Matches {
		st := stateOf(an, m.QueryKey)
		sev := any("unknown")
		if len(m.Record.Severity) > 0 {
			sev = m.Record.Severity
		}
		withdrawn := any(m.Withdrawn)
		aliases, related := m.Record.Aliases, m.Record.Related
		if aliases == nil {
			aliases = []string{}
		}
		if related == nil {
			related = []string{}
		}
		evID := fmt.Sprintf("%s.adv%d", t.TaskID, i+1)
		obs := fmt.Sprintf("OSV returned %s for %s %s in the captured batch result.", m.ID, st.Module, st.Version)
		if m.Withdrawn {
			obs += " The record is withdrawn."
		}
		res.Evidence = append(res.Evidence, EvidenceItem{EvidenceID: evID, Dimension: "inventory", Kind: "advisory_match",
			Subject: subject(st), ArtifactRef: bundleRef, Locator: "osv#" + m.QueryKey + "#" + m.ID, Observation: obs,
			CollectionMethod: method(tableDigest),
			Scope:            "Package/version match as returned by OSV for the captured query; the capture is the only source.",
			Limitations: []string{"A package/version match is not code use or exploitability.",
				"Advisory knowledge time is the capture time; later advisory changes are not reflected."},
			ObservedAt: stamp,
			Details: map[string]any{"query_key": m.QueryKey, "matched_version": st.Version, "vuln_id": m.ID,
				"aliases": aliases, "related": related, "record_artifact": m.RecordDigest, "withdrawn": withdrawn,
				"severity": sev, "affected_events": m.Events, "range_check": m.RangeCheck}})
		if m.Withdrawn {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s is withdrawn and is not counted as an active match for %s.", m.ID, m.QueryKey))
			continue
		}
		status, expl := "supported", "Supported by advisory_match evidence "+evID+"; OSV returned this record for the queried version."
		if m.RangeCheck == "inconsistent" {
			status, expl = "unknown", "OSV returned the record but its recorded SEMVER events do not include the queried version; not treated as a supported match."
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: recorded range events are inconsistent with %s %s.", m.ID, st.Module, st.Version))
		}
		activeSeen++
		res.Claims = append(res.Claims, Claim{ClaimID: fmt.Sprintf("%s.cl%d", t.TaskID, i+1), Type: "advisory_matches_version",
			Dimension: "inventory", Proposition: fmt.Sprintf("OSV returned %s for %s %s in this capture.", m.ID, st.Module, st.Version),
			EvidenceIDs: []string{evID}, Status: status, Explanation: expl, VulnID: m.ID})
	}

	// osv_query_complete: one item for the whole bundle.
	qEntries := make([]map[string]any, 0, len(an.Queries))
	for _, q := range an.Queries {
		if q.SkipReason != "" {
			continue
		}
		pages := q.Pages
		if pages < 1 {
			pages = 1
		}
		qEntries = append(qEntries, map[string]any{"query_key": q.Key, "pages": pages, "all_pages_complete": q.Complete,
			"returned_count": q.Returned, "active_count": q.Active})
	}
	qcID := t.TaskID + ".qc"
	if len(qEntries) > 0 {
		anyState := an.Queries[0]
		res.Evidence = append(res.Evidence, EvidenceItem{EvidenceID: qcID, Dimension: "inventory", Kind: "osv_query_complete",
			Subject: subject(anyState), ArtifactRef: bundleRef, Locator: "osv#queries",
			Observation:      fmt.Sprintf("%d OSV queries evaluated from the captured rounds.", len(qEntries)),
			CollectionMethod: method(tableDigest), Scope: "Completeness of the captured OSV batch queries.",
			Limitations: []string{"Completeness refers to the capture only."}, ObservedAt: stamp,
			Details: map[string]any{"capture_set_id": bundle.CaptureSetID, "queries": qEntries}})
	}
	missing := 0
	for _, q := range an.Queries {
		switch {
		case q.SkipReason != "":
			missing++
			res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
				Reason: q.SkipReason, QueryKey: q.Key, Detail: fmt.Sprintf("%s was not queried: %s.", q.Key, q.SkipReason)})
		case !q.Complete:
			missing++
			res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
				Reason: "incomplete_query", QueryKey: q.Key, Detail: q.Failed})
		}
	}
	for _, u := range an.Unavailable {
		missing++
		res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
			Reason: "record_unavailable", QueryKey: u.QueryKey, Detail: u.ID + ": " + u.Detail})
	}
	blocked := map[string]bool{}
	for _, m := range res.MissingEvidence {
		if m.QueryKey != "" {
			blocked[m.QueryKey] = true
		}
	}
	for i, q := range an.Queries {
		if q.SkipReason != "" || !q.Complete || blocked[q.Key] || q.Returned != 0 {
			continue
		}
		res.Claims = append(res.Claims, Claim{ClaimID: fmt.Sprintf("%s.zero%d", t.TaskID, i+1), Type: "no_advisory_match_returned",
			Dimension: "inventory", Proposition: emptyResultText, EvidenceIDs: []string{qcID}, Status: "supported",
			Explanation: "Query " + q.Key + " completed all pages and returned no IDs in this capture; this is not a statement about code use or later advisories.",
			QueryKey:    q.Key})
	}
	evaluated := len(an.Matches) > 0
	for _, q := range an.Queries {
		evaluated = evaluated || q.Complete
	}
	if !evaluated {
		// Nothing could be evaluated: a failed result with its gaps, no claims, no evidence.
		res.Errors = append(res.Errors, DomainError{Code: "worker_failed", Message: "No query could be evaluated from the bundle.", Retryable: false})
		res.Evidence, res.Claims = []EvidenceItem{}, []Claim{}
		return s.finishV2(res, tokens, "failed", "Failed: no OSV query could be evaluated.")
	}
	if len(res.MissingEvidence) > 0 {
		return s.finishV2(res, tokens, "partial", fmt.Sprintf("Partial: %d match(es); %d gap(s) left unknown.", activeSeen, len(res.MissingEvidence)))
	}
	return s.finishV2(res, tokens, "complete", fmt.Sprintf("Complete: %d active match(es) across %d queries.", activeSeen, len(qEntries)))
}

func stateOf(an *osvAnalysis, key string) *osvQueryState {
	for _, q := range an.Queries {
		if q.Key == key {
			return q
		}
	}
	return &osvQueryState{Key: key}
}
