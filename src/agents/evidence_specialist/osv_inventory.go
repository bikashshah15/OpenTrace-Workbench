package main

// osv_inventory_match (I3-REQ-06): offline interpretation of captured OSV batch results and full advisory
// records for exact registry versions across Go, npm and PyPI. B reads only the digests listed in the
// bundle manifest it was given. Query keys come from the captured requests (`ecosystem|name|version`),
// never from an assumption. A positive or withdrawn-only result is never turned into an empty one, and a
// zero-result claim exists only for a complete, exact, unblocked query.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	opOSVInventory     = "osv_inventory_match"
	osvQueryKeyForm    = "ecosystem|name|version"
	osvItemBudget      = 900 // evidence + claims per task (contract section 3.6 item 5)
	osvMaxPlannedQuery = 100
)

func init() { registerV3(opOSVInventory, "inventory", osvInventoryHandler) }

type osvPlanned3 struct {
	QueryKey        string `json:"query_key"`
	Ecosystem       string `json:"ecosystem"`
	Name            string `json:"name"`
	VersionQueried  string `json:"version_queried"`
	VersionOriginal string `json:"version_original"`
}

type osvBundle3 struct {
	Schema             string                  `json:"schema"`
	Kind               string                  `json:"kind"`
	CaptureSetID       string                  `json:"capture_set_id"`
	PlannedQueryDigest string                  `json:"planned_query_digest"`
	QueryKeyForm       string                  `json:"query_key_form"`
	Queries            []osvPlanned3           `json:"queries"`
	Rounds             []osvRound              `json:"rounds"`
	Records            map[string]osvRecordRef `json:"records"`
}

// v3QueryKey derives `ecosystem|name|version` from a captured request query.
func v3QueryKey(q osvQuery) string {
	name := q.Package.Name
	if name == "" {
		name = "purl:" + q.Package.Purl // never matches a planned key; the query is then reported unseen
	}
	if q.Package.Ecosystem == "PyPI" {
		name = pep503(name)
	}
	return q.Package.Ecosystem + "|" + name + "|" + q.Version
}

// recordSeverityLabel returns the recorded database_specific.severity string, or "".
func recordSeverityLabel(rec *osvRecord) string {
	if rec.DatabaseSpecific == nil {
		return ""
	}
	if s, ok := rec.DatabaseSpecific["severity"].(string); ok {
		return s
	}
	return ""
}

// v3RangeCheck evaluates the recorded events for the affected entry whose package matches the queried
// identity (PyPI names compare after PEP 503 normalization).
func v3RangeCheck(rec *osvRecord, eco, name, version string) (string, []map[string]any) {
	matched := name
	for _, a := range rec.Affected {
		if a.Package.Ecosystem != eco {
			continue
		}
		an := a.Package.Name
		if an == name || (eco == "PyPI" && pep503(an) == name) {
			matched = an
			break
		}
	}
	return rangeCheck(rec, matched, version)
}

func osvInventoryHandler(s *Server, ctx context.Context, t *TaskRequest, jobDeadline time.Time, tokens []Part) *Message {
	res := s.newV3Result(t, opOSVInventory)
	unsupportedRequirements(res, t, opOSVInventory, "inventory")
	rej := func(code, msg string) *Message { return s.rejectV3(tokens, false, code, msg, t.TaskID, t.RunID) }
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
	var b3 osvBundle3
	if json.Unmarshal(raw, &b3) != nil || b3.Kind != "osv" || b3.QueryKeyForm != osvQueryKeyForm {
		return s.failV2(res, t, tokens, "artifact_integrity_failure", "The bundle manifest is not an osv bundle of this key form.")
	}
	if b3.CaptureSetID != t.CaptureSetID {
		return rej("capture_mismatch", "The bundle's capture_set_id differs from the task's.")
	}
	if len(b3.Queries) == 0 || len(b3.Queries) > osvMaxPlannedQuery {
		return rej("invalid_request", fmt.Sprintf("A bundle plans 1..%d queries.", osvMaxPlannedQuery))
	}
	planned := map[string]osvPlanned3{}
	bundle := osvBundle{Schema: b3.Schema, Kind: "osv", CaptureSetID: b3.CaptureSetID, Rounds: b3.Rounds, Records: b3.Records, keyFn: v3QueryKey}
	ecoSet := map[string]bool{}
	for _, q := range b3.Queries {
		want := q.Ecosystem + "|" + q.Name + "|" + q.VersionQueried
		if q.QueryKey != want || !validIdentity(q.Ecosystem, q.Name) || !validText(q.VersionQueried, maxVersionBytes) || q.VersionQueried == "" ||
			!validText(q.VersionOriginal, maxVersionBytes) || (q.Ecosystem == "PyPI" && pep503(q.Name) != q.Name) {
			// A name or version that is not valid for its ecosystem is never a query component.
			return rej("invalid_request", "A planned query has an invalid ecosystem, name or version.")
		}
		if _, dup := planned[q.QueryKey]; dup {
			return rej("invalid_request", "A planned query is duplicated.")
		}
		planned[q.QueryKey] = q
		ecoSet[q.Ecosystem] = true
		bundle.Queries = append(bundle.Queries, osvPlanned{QueryKey: q.QueryKey, Module: q.Name, Version: q.VersionQueried})
	}
	if ctx.Err() != nil || time.Now().After(jobDeadline) {
		return s.failV2(res, t, tokens, "worker_timeout", "The task deadline passed before analysis.")
	}
	an := analyzeOSV(&bundle, osvStoreReader{s.store})
	stamp := s.now().Format(timeLayout)
	req := firstRequirement(t, "inventory")
	method := func(out string) CollectionMethod {
		return CollectionMethod{Tool: opOSVInventory, ToolVersion: toolVersionV3, ArgvTemplate: []string{opOSVInventory, "<bundle-manifest>"}, OutputArtifact: out}
	}

	// Which queries are blocked, by what reason, before any evidence is spent on them.
	type gap struct{ reason, detail string }
	gaps := map[string]gap{}
	for _, q := range an.Queries {
		if q.Complete {
			continue
		}
		reason := "incomplete_query"
		if strings.Contains(q.Failed, "HTTP 400") {
			reason = "query_rejected"
		}
		gaps[q.Key] = gap{reason, q.Failed}
	}
	unavailable := map[string][]osvUnavailable{}
	for _, u := range an.Unavailable {
		unavailable[u.QueryKey] = append(unavailable[u.QueryKey], u)
	}
	matchesBy := map[string][]osvMatch{}
	for _, m := range an.Matches {
		matchesBy[m.QueryKey] = append(matchesBy[m.QueryKey], m)
	}

	// Output guard: evidence plus claims per task stay under the budget; the rest are marked, never dropped.
	items := 2 // osv_inventory_scope and osv_query_complete
	limited := map[string]bool{}
	for _, q := range an.Queries {
		need := 0
		if q.Complete {
			need = 2 * len(matchesBy[q.Key])
			if q.Returned == 0 && len(unavailable[q.Key]) == 0 {
				need = 1 // the zero-result claim
			}
		}
		if items+need > osvItemBudget {
			limited[q.Key] = true
			continue
		}
		items += need
	}

	type tableQuery struct {
		QueryKey        string   `json:"query_key"`
		Ecosystem       string   `json:"ecosystem"`
		Name            string   `json:"name"`
		VersionQueried  string   `json:"version_queried"`
		VersionOriginal string   `json:"version_original"`
		VersionState    string   `json:"version_state"`
		Pages           int      `json:"pages"`
		Complete        bool     `json:"all_pages_complete"`
		Returned        int      `json:"returned_count"`
		Active          int      `json:"active_count"`
		IDs             []string `json:"ids"`
		Failure         string   `json:"failure,omitempty"`
	}
	table := struct {
		Schema       string           `json:"schema"`
		CaptureSetID string           `json:"capture_set_id"`
		Queries      []tableQuery     `json:"queries"`
		Matches      []map[string]any `json:"matches"`
	}{Schema: "opentrace.osv_inventory_table/1", CaptureSetID: b3.CaptureSetID, Queries: []tableQuery{}, Matches: []map[string]any{}}
	for _, q := range an.Queries {
		p := planned[q.Key]
		ids := append([]string{}, q.IDs...)
		sort.Strings(ids)
		table.Queries = append(table.Queries, tableQuery{q.Key, p.Ecosystem, p.Name, p.VersionQueried, p.VersionOriginal, "exact", q.Pages,
			q.Complete, q.Returned, q.Active, ids, q.Failed})
	}
	for _, m := range an.Matches {
		table.Matches = append(table.Matches, map[string]any{"query_key": m.QueryKey, "vuln_id": m.ID, "withdrawn": m.Withdrawn,
			"range_check": m.RangeCheck, "record_artifact": m.RecordDigest})
	}
	tableDigest, err := s.addProduced(res, t, canonicalJSON(table), "application/json", "match_table", serviceID+"/"+opOSVInventory, ref.Digest)
	if err != nil {
		return s.failV2(res, t, tokens, "output_too_large", "The match table exceeds the artifact budget.")
	}

	bundleRef := ArtifactRef{Digest: ref.Digest, MediaType: ref.MediaType, Role: "osv_bundle_manifest"}
	evN, claimN := 0, 0
	addEvidence := func(kind, locator, observation string, subject Subject, details map[string]any) string {
		evN++
		id := fmt.Sprintf("%s.ev%d", t.TaskID, evN)
		res.Evidence = append(res.Evidence, EvidenceItem{EvidenceID: id, Dimension: "inventory", Kind: kind, Subject: subject, ArtifactRef: bundleRef,
			Locator: locator, Observation: observation, CollectionMethod: method(tableDigest),
			Scope: "Package/version match as returned by OSV for the captured query; the capture is the only source.",
			Limitations: []string{"A package/version match is not code use, reachability or exploitability.",
				"Advisory knowledge time is the capture time; later advisory changes are not reflected."},
			ObservedAt: stamp, Details: details})
		return id
	}
	addClaim := func(typ, proposition string, evIDs []string, status, expl, vuln, queryKey string) {
		claimN++
		res.Claims = append(res.Claims, Claim{ClaimID: fmt.Sprintf("%s.cl%d", t.TaskID, claimN), Type: typ, Dimension: "inventory",
			Proposition: proposition, EvidenceIDs: evIDs, Status: status, Explanation: expl, VulnID: vuln, QueryKey: queryKey})
	}
	subjectOf := func(key string) Subject {
		p := planned[key]
		return Subject{Module: p.Name, Version: p.VersionQueried}
	}

	captured := 0
	for _, q := range an.Queries {
		if q.Seen {
			captured++
		}
	}
	ecos := make([]string, 0, len(ecoSet))
	for e := range ecoSet {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	addEvidence("osv_inventory_scope", "osv#scope", fmt.Sprintf("%d planned OSV queries; %d appear in the captured requests.", len(b3.Queries), captured),
		Subject{Module: "osv", Version: "scope"}, map[string]any{"capture_set_id": b3.CaptureSetID, "planned_query_digest": b3.PlannedQueryDigest,
			"query_key_form": osvQueryKeyForm, "ecosystems": ecos, "queries_planned": len(b3.Queries), "queries_captured": captured})

	activeSeen := 0
	for _, q := range an.Queries {
		if limited[q.Key] || !q.Complete {
			continue
		}
		p := planned[q.Key]
		for _, m := range matchesBy[q.Key] {
			sev := any("unknown")
			if len(m.Record.Severity) > 0 {
				sev = m.Record.Severity
			}
			var label any
			if l := recordSeverityLabel(m.Record); l != "" {
				label = l
			}
			aliases, related := m.Record.Aliases, append(append([]string{}, m.Record.Related...), m.Record.Upstream...)
			if aliases == nil {
				aliases = []string{}
			}
			rc, events := v3RangeCheck(m.Record, p.Ecosystem, p.Name, p.VersionQueried)
			obs := fmt.Sprintf("OSV returned %s for %s %s in the captured batch result.", m.ID, p.Name, p.VersionQueried)
			if m.Withdrawn {
				obs += " The record is withdrawn."
			}
			evID := addEvidence("advisory_match", "osv#"+q.Key+"#"+m.ID, obs, subjectOf(q.Key), map[string]any{
				"query_key": q.Key, "matched_version": p.VersionQueried, "vuln_id": m.ID, "aliases": aliases, "related": related,
				"record_artifact": m.RecordDigest, "withdrawn": m.Withdrawn, "severity": sev, "database_specific_severity": label,
				"affected_events": events, "range_check": rc, "ecosystem": p.Ecosystem, "package": p.Name,
				"version_queried": p.VersionQueried, "version_original": p.VersionOriginal})
			if m.Withdrawn {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s is withdrawn and is not counted as an active match for %s.", m.ID, q.Key))
				continue
			}
			status, expl := "supported", "Supported by advisory_match evidence "+evID+"; OSV returned this record for the queried version."
			if rc == "inconsistent" {
				status, expl = "unknown", "OSV returned the record but its recorded SEMVER events do not include the queried version; not treated as a supported match."
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: recorded range events are inconsistent with %s %s.", m.ID, p.Name, p.VersionQueried))
			}
			activeSeen++
			addClaim("advisory_matches_version", fmt.Sprintf("OSV returned %s for %s %s in this capture.", m.ID, p.Name, p.VersionQueried),
				[]string{evID}, status, expl, m.ID, "")
		}
	}

	// osv_query_complete: one item for the whole bundle, one entry per planned query that was evaluated.
	entries := []map[string]any{}
	for _, q := range an.Queries {
		if limited[q.Key] {
			continue
		}
		pages := q.Pages
		if pages < 1 {
			pages = 1
		}
		entries = append(entries, map[string]any{"query_key": q.Key, "pages": pages, "all_pages_complete": q.Complete,
			"returned_count": q.Returned, "active_count": q.Active, "version_state": "exact"})
	}
	qcID := ""
	if len(entries) > 0 {
		qcID = addEvidence("osv_query_complete", "osv#queries", fmt.Sprintf("%d OSV queries evaluated from the captured rounds.", len(entries)),
			subjectOf(an.Queries[0].Key), map[string]any{"capture_set_id": b3.CaptureSetID, "queries": entries})
	}

	for _, q := range an.Queries {
		switch {
		case limited[q.Key]:
			res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
				Reason: "output_limit", QueryKey: q.Key, Detail: q.Key + " was not reported: the evidence budget of this task was reached."})
		case !q.Complete:
			g := gaps[q.Key]
			res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
				Reason: g.reason, QueryKey: q.Key, Detail: g.detail})
		}
		for _, u := range unavailable[q.Key] {
			res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
				Reason: "record_unavailable", QueryKey: q.Key, Detail: u.ID + ": " + u.Detail})
		}
	}
	blocked := map[string]bool{}
	for _, m := range res.MissingEvidence {
		if m.QueryKey != "" {
			blocked[m.QueryKey] = true
		}
	}
	for _, q := range an.Queries {
		if limited[q.Key] || !q.Complete || blocked[q.Key] || q.Returned != 0 || qcID == "" {
			continue
		}
		addClaim("no_advisory_match_returned", emptyResultText, []string{qcID}, "supported",
			"Query "+q.Key+" completed all pages and returned no IDs in this capture; this is not a statement about code use or later advisories.", "", q.Key)
	}
	evaluated := len(an.Matches) > 0
	for _, q := range an.Queries {
		evaluated = evaluated || (q.Complete && !limited[q.Key])
	}
	if !evaluated {
		res.Errors = append(res.Errors, DomainError{Code: "worker_failed", Message: "No query could be evaluated from the bundle.", Retryable: false})
		res.Evidence, res.Claims = []EvidenceItem{}, []Claim{}
		return s.finishV2(res, tokens, "failed", "Failed: no OSV query could be evaluated.")
	}
	if len(res.MissingEvidence) > 0 {
		return s.finishV2(res, tokens, "partial", fmt.Sprintf("Partial: %d active match(es); %d gap(s) left unknown.", activeSeen, len(res.MissingEvidence)))
	}
	return s.finishV2(res, tokens, "complete", fmt.Sprintf("Complete: %d active match(es) across %d queries.", activeSeen, len(entries)))
}
