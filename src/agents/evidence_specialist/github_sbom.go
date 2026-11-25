package main

// github_sbom_import (I3-REQ-07): offline interpretation of one repository's captured GitHub asynchronous
// SBOM exchange. B reads only the digests listed in the bundle. The acquisition state history is derived
// deterministically from the captured entries; the hosted document is ALWAYS recorded as unbound: a
// branch-head observation, an agreeing comparison or a downloaded document never binds it to the pinned
// commit. Hosted rows are inventory only: they are never advisory-query inputs in this increment.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	opGitHubSBOM       = "github_sbom_import"
	maxHostedBytes     = 4 << 20
	maxHostedPackages  = 20000
	maxPollsBeforeStop = 8
)

func init() { registerV3(opGitHubSBOM, "inventory", githubSBOMHandler) }

var (
	sbomURLRE     = regexp.MustCompile(`^https://api\.github\.com/repos/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/dependency-graph/sbom/fetch-report/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)
	semverExact   = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.+-]+)?$`)
	pep440Exact   = regexp.MustCompile(`^\d+(\.\d+)*((\.|-|_)?(a|b|rc|alpha|beta|pre|preview|post|rev|r|dev)\d*)*(\+[A-Za-z0-9.]+)?$`)
	spdxIDRE      = regexp.MustCompile(`^SPDXRef-[A-Za-z0-9.-]{1,200}$`)
	failureReason = map[string]string{"credential_unavailable": "credential_unavailable", "forbidden": "forbidden", "not_found": "not_found",
		"rate_limited": "rate_limited", "timeout": "timeout", "redirect_refused": "redirect_refused", "invalid_response": "invalid_response",
		"report_too_large": "report_too_large", "http_error": "http_error"}
)

type hostedEntry struct {
	Seq      int               `json:"seq"`
	Kind     string            `json:"kind"`
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Status   *int              `json:"status"`
	Headers  map[string]string `json:"headers"`
	Response string            `json:"response"`
	Bytes    int               `json:"bytes"`
	Hops     []map[string]any  `json:"redirect_hops"`
}

type hostedBundle struct {
	Schema          string        `json:"schema"`
	Kind            string        `json:"kind"`
	CaptureSetID    string        `json:"capture_set_id"`
	Repo            string        `json:"repo"`
	RequestedPin    string        `json:"requested_pin"`
	CredentialClass string        `json:"credential_class"`
	Entries         []hostedEntry `json:"entries"`
}

type hostHistory struct {
	State        string
	Seq          int
	Status       *int
	Detail       string
	LocationHost string
	LocationPath string
}

func (h hostHistory) asMap() map[string]any {
	m := map[string]any{"state": h.State, "seq": h.Seq, "status": nil, "detail": h.Detail}
	if h.Status != nil {
		m["status"] = *h.Status
	}
	if h.LocationHost != "" {
		m["location_host"], m["location_path"] = h.LocationHost, h.LocationPath
	}
	return m
}

type hostedFacts struct {
	History      []hostHistory
	State        string
	SBOMURL      string
	DownloadSeq  int
	DownloadBody string // artifact digest
	DownloadSize int
	HeadBefore   string
	HeadAfter    string
	headSeen     int
	Metadata     map[string]any
}

// classifyFailure maps a non-success HTTP exchange to a terminal state (contract section 3.7 rules 3 and 4).
func classifyFailure(e hostedEntry, body []byte) string {
	status := 0
	if e.Status != nil {
		status = *e.Status
	}
	switch {
	case status == 403 || status == 429:
		if e.Headers["x-ratelimit-remaining"] == "0" || e.Headers["retry-after"] != "" || strings.Contains(strings.ToLower(string(body)), "rate limit") {
			return "rate_limited"
		}
		return "forbidden"
	case status == 404:
		return "not_found"
	}
	return "http_error"
}

// deriveHosted walks the captured entries in order and derives the state history.
func (s *Server) deriveHosted(b *hostedBundle) *hostedFacts {
	f := &hostedFacts{State: "not_requested"}
	terminal := false
	add := func(h hostHistory) {
		f.History = append(f.History, h)
		f.State = h.State
		if h.State != "generate_requested" && h.State != "pending" && h.State != "ready" && h.State != "downloaded" {
			terminal = true
		}
	}
	read := func(e hostedEntry, max int) []byte {
		if e.Response == "" {
			return nil
		}
		d, err := s.store.ReadMax(e.Response, max)
		if err != nil {
			return nil
		}
		return d
	}
	polls := 0
	var generateSeq int
	for _, e := range b.Entries {
		if terminal {
			break
		}
		status := e.Status
		code := 0
		if status != nil {
			code = *status
		}
		switch e.Kind {
		case "github_repo_metadata":
			if code == 200 {
				var m map[string]any
				if json.Unmarshal(read(e, 1<<20), &m) == nil {
					f.Metadata = map[string]any{}
					for _, k := range []string{"id", "default_branch", "archived", "fork"} {
						if v, ok := m[k]; ok {
							f.Metadata[k] = v
						}
					}
					if lic, ok := m["license"].(map[string]any); ok {
						f.Metadata["license_spdx_id"] = lic["spdx_id"]
					}
				}
			}
		case "github_branch_head":
			if code == 200 {
				var m struct {
					Commit struct {
						SHA string `json:"sha"`
					} `json:"commit"`
				}
				if json.Unmarshal(read(e, 1<<20), &m) == nil && hex40RE.MatchString(m.Commit.SHA) {
					f.headSeen++
					if f.headSeen == 1 && (generateSeq == 0) {
						f.HeadBefore = m.Commit.SHA
					} else {
						f.HeadAfter = m.Commit.SHA
					}
				}
			}
		case "github_sbom_generate":
			generateSeq = e.Seq
			if code != 201 {
				add(hostHistory{State: classifyFailure(e, read(e, 1<<16)), Seq: e.Seq, Status: status, Detail: "generate-report returned a non-201 response"})
				continue
			}
			var m struct {
				URL string `json:"sbom_url"`
			}
			if json.Unmarshal(read(e, 1<<16), &m) != nil {
				add(hostHistory{State: "invalid_response", Seq: e.Seq, Status: status, Detail: "generate-report body is not valid JSON"})
				continue
			}
			mm := sbomURLRE.FindStringSubmatch(m.URL)
			if mm == nil || mm[1]+"/"+mm[2] != b.Repo {
				add(hostHistory{State: "invalid_response", Seq: e.Seq, Status: status, Detail: "sbom_url is not the fetch-report URL of the requested repository; it was never fetched"})
				continue
			}
			f.SBOMURL = m.URL
			add(hostHistory{State: "generate_requested", Seq: e.Seq, Status: status})
		case "github_sbom_poll":
			if f.State != "generate_requested" && f.State != "pending" {
				add(hostHistory{State: "invalid_response", Seq: e.Seq, Status: status, Detail: "poll without an accepted generate request"})
				continue
			}
			polls++
			switch code {
			case 202:
				add(hostHistory{State: "pending", Seq: e.Seq, Status: status})
			case 302:
				h := hostHistory{State: "ready", Seq: e.Seq, Status: status}
				if len(e.Hops) > 0 {
					if v, ok := e.Hops[0]["host"].(string); ok && validText(v, 253) {
						h.LocationHost = v
					}
					if v, ok := e.Hops[0]["path"].(string); ok && validText(v, 512) {
						h.LocationPath = v
					}
				}
				if h.LocationHost == "" {
					h.State, h.Detail = "invalid_response", "302 without a recorded Location host"
				}
				add(h)
			default:
				add(hostHistory{State: classifyFailure(e, read(e, 1<<16)), Seq: e.Seq, Status: status, Detail: "poll returned an unexpected response"})
			}
		case "github_sbom_download":
			if f.State != "ready" {
				add(hostHistory{State: "invalid_response", Seq: e.Seq, Status: status, Detail: "download without a ready report"})
				continue
			}
			switch {
			case code == 200 && e.Bytes > maxHostedBytes:
				add(hostHistory{State: "report_too_large", Seq: e.Seq, Status: status, Detail: fmt.Sprintf("%d bytes exceed the %d limit", e.Bytes, maxHostedBytes)})
			case code == 200 && e.Response != "":
				f.DownloadSeq, f.DownloadBody, f.DownloadSize = e.Seq, e.Response, e.Bytes
				add(hostHistory{State: "downloaded", Seq: e.Seq, Status: status})
			case code >= 300 && code < 400:
				add(hostHistory{State: "redirect_refused", Seq: e.Seq, Status: status, Detail: "the download host redirected; not followed"})
			default:
				add(hostHistory{State: classifyFailure(e, nil), Seq: e.Seq, Status: status, Detail: "download returned an unexpected response"})
			}
		case "github_event":
			var ev struct {
				Event  string `json:"event"`
				Detail string `json:"detail"`
				Host   string `json:"host"`
			}
			if json.Unmarshal(read(e, 1<<16), &ev) != nil {
				add(hostHistory{State: "invalid_response", Seq: e.Seq, Detail: "unreadable acquisition event"})
				continue
			}
			state := ev.Event
			if state == "budget" || state == "rate_limit_stop" {
				state = "rate_limited"
			}
			if _, terminalFailure := failureReason[state]; !terminalFailure || !validText(ev.Detail, 300) {
				// an event can only record a terminal failure; a forged success state is invalid
				state = "invalid_response"
			}
			h := hostHistory{State: state, Seq: e.Seq, Detail: ev.Event}
			if state == "redirect_refused" && validText(ev.Host, 253) {
				h.LocationHost = ev.Host
			}
			add(h)
		}
	}
	if f.State == "pending" && polls >= maxPollsBeforeStop {
		f.History = append(f.History, hostHistory{State: "timeout", Seq: 0, Detail: fmt.Sprintf("still processing after %d polls", polls)})
		f.State = "timeout"
	}
	return f
}

type hostedRow struct {
	SPDXID          string  `json:"spdx_id"`
	NameOriginal    string  `json:"name_original"`
	NameNormalized  string  `json:"name_normalized"`
	Ecosystem       string  `json:"ecosystem"`
	VersionOriginal *string `json:"version_original"`
	VersionState    string  `json:"version_state"`
	Purl            *string `json:"purl"`
	SourcePath      *string `json:"source_path"`
}

type hostedTable struct {
	Schema string      `json:"schema"`
	Repo   string      `json:"repo"`
	Lane   string      `json:"lane"`
	Rows   []hostedRow `json:"rows"`
}

// parsePurl splits pkg:type/namespace/name@version?qualifiers#subpath into (type, name, version).
func parsePurl(p string) (typ, name, version string, ok bool) {
	if !strings.HasPrefix(p, "pkg:") || !validText(p, 1024) {
		return
	}
	rest := p[4:]
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i > 0 && i > strings.IndexByte(rest, '/') {
		version, rest = rest[i+1:], rest[:i]
		if v, err := url.PathUnescape(version); err == nil {
			version = v
		}
	}
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return
	}
	typ = strings.ToLower(rest[:slash])
	n, err := url.PathUnescape(rest[slash+1:])
	if err != nil || n == "" {
		return
	}
	return typ, n, version, true
}

func hostedVersionState(eco, v string) string {
	switch {
	case v == "":
		return "missing"
	case eco == "Go" || eco == "npm":
		if semverExact.MatchString(v) && (eco != "Go" || strings.HasPrefix(v, "v")) {
			return "exact"
		}
	case eco == "PyPI":
		if pep440Exact.MatchString(v) {
			return "exact"
		}
	default:
		return "unsupported_ecosystem"
	}
	return "range"
}

type spdxDoc struct {
	SPDXVersion  string `json:"spdxVersion"`
	Comment      string `json:"comment"`
	CreationInfo struct {
		Created  string   `json:"created"`
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	Packages []struct {
		SPDXID       string `json:"SPDXID"`
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		ExternalRefs []struct {
			Category string `json:"referenceCategory"`
			Type     string `json:"referenceType"`
			Locator  string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
	Relationships []struct {
		From string `json:"spdxElementId"`
		Type string `json:"relationshipType"`
		To   string `json:"relatedSpdxElement"`
	} `json:"relationships"`
}

// parseSPDX returns the document, its wrapper form and a failure code ("" on success).
func parseSPDX(data []byte) (*spdxDoc, string, string) {
	if !jsonDepthOK(data, maxJSONDepth) {
		return nil, "", "invalid_response"
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil {
		return nil, "", "invalid_response"
	}
	wrapper, raw := "bare", json.RawMessage(data)
	if inner, ok := top["sbom"]; ok {
		wrapper, raw = "sbom", inner
	}
	var d spdxDoc
	if json.Unmarshal(raw, &d) != nil {
		return nil, wrapper, "invalid_response"
	}
	if !strings.HasPrefix(d.SPDXVersion, "SPDX-2.") {
		return &d, wrapper, "unsupported_spdx_version"
	}
	return &d, wrapper, ""
}

func buildHostedTable(repo string, d *spdxDoc) (rows []hostedRow, unparsed map[string]int) {
	unparsed = map[string]int{}
	roots := map[string]bool{}
	for _, r := range d.Relationships {
		if r.Type == "DESCRIBES" && strings.HasPrefix(r.From, "SPDXRef-DOCUMENT") {
			roots[r.To] = true
		}
	}
	seen := map[string]bool{}
	for _, p := range d.Packages {
		if roots[p.SPDXID] {
			continue
		}
		if len(rows) >= maxHostedPackages {
			unparsed["output_limit_rows"]++
			continue
		}
		if !spdxIDRE.MatchString(p.SPDXID) || !validText(p.Name, maxNameBytes) || !validText(p.VersionInfo, maxVersionBytes) {
			unparsed["rejected_package"]++
			continue
		}
		if seen[p.SPDXID] {
			unparsed["duplicate_spdx_id"]++
			continue
		}
		seen[p.SPDXID] = true
		row := hostedRow{SPDXID: p.SPDXID, NameOriginal: p.Name, NameNormalized: p.Name, Ecosystem: "unsupported", VersionState: "unsupported_ecosystem"}
		if p.VersionInfo != "" {
			v := p.VersionInfo
			row.VersionOriginal = &v
		}
		var purl, ptype, pname, pver string
		for _, x := range p.ExternalRefs {
			if strings.EqualFold(x.Type, "purl") {
				if t, n, v, ok := parsePurl(x.Locator); ok {
					purl, ptype, pname, pver = x.Locator, t, n, v
					break
				}
			}
		}
		if purl != "" {
			l := purl
			row.Purl = &l
		}
		eco := map[string]string{"golang": "Go", "npm": "npm", "pypi": "PyPI"}[ptype]
		if eco == "" {
			row.Ecosystem, row.VersionState = "unsupported_ecosystem", "unsupported_ecosystem"
			if ptype != "" {
				row.NameNormalized = ptype + "/" + pname
			}
		} else {
			row.Ecosystem = eco
			row.NameNormalized = pname
			if eco == "PyPI" {
				row.NameNormalized = pep503(pname)
			}
			if !validIdentity(eco, pname) {
				row.VersionState = "unresolved_identity"
			} else {
				row.VersionState = hostedVersionState(eco, p.VersionInfo)
				_ = pver
			}
		}
		if !validText(row.NameNormalized, maxNameBytes) {
			unparsed["rejected_package"]++
			continue
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].SPDXID < rows[j].SPDXID })
	return rows, unparsed
}

func githubSBOMHandler(s *Server, ctx context.Context, t *TaskRequest, jobDeadline time.Time, tokens []Part) *Message {
	res := s.newV3Result(t, opGitHubSBOM)
	unsupportedRequirements(res, t, opGitHubSBOM, "inventory")
	rej := func(code, msg string) *Message { return s.rejectV3(tokens, false, code, msg, t.TaskID, t.RunID) }
	if *t.Budget.MaxWorkerJobs < 1 {
		return s.failV2(res, t, tokens, "budget_exhausted", "The task budget allows no worker job.")
	}
	ref := inputByRole(t, "hosted_bundle_manifest")
	if ref == nil {
		return rej("invalid_request", "A hosted_bundle_manifest input is required.")
	}
	raw, err := s.store.ReadMax(ref.Digest, maxBundleBytes)
	if err != nil {
		code := "artifact_not_found"
		if errors.Is(err, errIntegrity) {
			code = "artifact_integrity_failure"
		}
		return s.failV2(res, t, tokens, code, "The bundle manifest could not be read from the store.")
	}
	var b hostedBundle
	if json.Unmarshal(raw, &b) != nil || b.Kind != "hosted" || !repoNameRE.MatchString(b.Repo) || len(b.Entries) > 64 {
		return s.failV2(res, t, tokens, "artifact_integrity_failure", "The bundle manifest is not a hosted bundle.")
	}
	switch {
	case b.CaptureSetID != t.CaptureSetID:
		return rej("capture_mismatch", "The bundle's capture_set_id differs from the task's.")
	case t.Context.RepoID != "github.com/"+b.Repo:
		return rej("context_mismatch", "The task context does not name the bundle's repository.")
	case t.Context.ObservedRevision != nil:
		// A hosted result is never bound to a revision: observed_revision stays null (V13).
		return rej("context_mismatch", "A hosted task must leave observed_revision null.")
	case !hex40RE.MatchString(b.RequestedPin) || t.Context.RequestedRevision != b.RequestedPin:
		return rej("context_mismatch", "requested_revision must be the pinned commit, recorded as context only.")
	}
	if ctx.Err() != nil || time.Now().After(jobDeadline) {
		return s.failV2(res, t, tokens, "worker_timeout", "The task deadline passed before analysis.")
	}
	cred := b.CredentialClass
	if cred != "unauthenticated" && cred != "token_read_only" && cred != "app" {
		cred = "unauthenticated"
	}
	facts := s.deriveHosted(&b)
	stamp := s.now().Format(timeLayout)
	req := firstRequirement(t, "inventory")
	bundleRef := ArtifactRef{Digest: ref.Digest, MediaType: ref.MediaType, Role: "hosted_bundle_manifest"}
	evN := 0
	addEvidence := func(kind, locator, observation string, subject Subject, output string, details map[string]any) string {
		evN++
		id := fmt.Sprintf("%s.ev%d", t.TaskID, evN)
		res.Evidence = append(res.Evidence, EvidenceItem{EvidenceID: id, Dimension: "inventory", Kind: kind, Subject: subject, ArtifactRef: bundleRef,
			Locator: locator, Observation: observation,
			CollectionMethod: CollectionMethod{Tool: kind, ToolVersion: toolVersionV3, ArgvTemplate: []string{kind, "<bundle-manifest>"}, OutputArtifact: output},
			Scope:            "The repository's current hosted dependency graph as captured; it is not bound to the pinned commit.",
			Limitations: []string{"Hosted and unbound: describes the repository when the report was generated, not the pinned commit.",
				"No manifest path is provided by the hosted report; inventory only, never an advisory-query input here."},
			ObservedAt: stamp, Details: details})
		return id
	}

	var rows []hostedRow
	unparsed := map[string]int{}
	spdxVersion, created, wrapper := any(nil), any(nil), any(nil)
	creators, comment := []string{}, any(nil)
	state := facts.State
	reportBytes := 0
	if state == "downloaded" {
		data, err := s.store.ReadMax(facts.DownloadBody, maxHostedBytes)
		if err != nil {
			state = "invalid_response"
			facts.History = append(facts.History, hostHistory{State: "invalid_response", Seq: facts.DownloadSeq, Detail: "the downloaded report could not be read from the store"})
		} else {
			reportBytes = len(data)
			doc, w, fail := parseSPDX(data)
			wrapper = w
			if doc != nil && doc.SPDXVersion != "" && validText(doc.SPDXVersion, 32) {
				spdxVersion = doc.SPDXVersion
			}
			if fail != "" {
				state = fail
				facts.History = append(facts.History, hostHistory{State: fail, Seq: facts.DownloadSeq, Detail: "the downloaded report was not accepted"})
			} else {
				if validText(doc.CreationInfo.Created, 64) {
					created = doc.CreationInfo.Created
				}
				for _, c := range doc.CreationInfo.Creators {
					if validText(c, 200) && len(creators) < 20 {
						creators = append(creators, c)
					}
				}
				if doc.Comment != "" && validText(doc.Comment, 2000) {
					comment = doc.Comment
				}
				rows, unparsed = buildHostedTable(b.Repo, doc)
			}
		}
	}
	history := make([]map[string]any, 0, len(facts.History))
	for _, h := range facts.History {
		history = append(history, h.asMap())
	}
	var before, after, moved any
	if facts.HeadBefore != "" {
		before = facts.HeadBefore
	}
	if facts.HeadAfter != "" {
		after = facts.HeadAfter
	}
	if facts.HeadBefore != "" && facts.HeadAfter != "" {
		moved = facts.HeadBefore != facts.HeadAfter
	}
	tableDigest := ""
	scopeDetails := map[string]any{"repo": b.Repo, "state": state, "revision_binding": "unbound", "document_binding": "unbound",
		"credential_class": cred, "spdx_version": spdxVersion, "created": created, "creators": creators, "document_comment": comment,
		"default_branch_head_before": before, "default_branch_head_after": after, "head_moved": moved, "requested_pin": b.RequestedPin,
		"acquisition_history": history, "report_bytes": reportBytes, "package_count": len(rows), "document_wrapper": wrapper}
	if facts.Metadata != nil {
		scopeDetails["github_api_metadata"] = facts.Metadata
	}
	if state == "downloaded" {
		table, err := canonicalAny(hostedTable{Schema: tableSchemaHosted, Repo: b.Repo, Lane: "hosted_unbound", Rows: nonNilRows(rows)})
		if err != nil || len(table) > maxTableBytes {
			state = "report_too_large"
			scopeDetails["state"] = state
			res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
				Reason: "output_limit", Detail: b.Repo + ": the hosted package table exceeds the artifact limit."})
			addEvidence("hosted_sbom_scope", "hosted#scope", b.Repo+": hosted report state "+state+".", Subject{Module: b.Repo, Version: b.RequestedPin}, ref.Digest, scopeDetails)
			return s.finishV2(res, tokens, "partial", "Partial: the hosted table was too large.")
		}
		tableDigest, err = s.addProduced(res, t, table, "application/json", "hosted_table", serviceID+"/"+opGitHubSBOM, ref.Digest)
		if err != nil {
			return s.failV2(res, t, tokens, "output_too_large", "The hosted table exceeds the artifact budget.")
		}
	}
	output := ref.Digest
	if tableDigest != "" {
		output = tableDigest
	}
	scopeID := addEvidence("hosted_sbom_scope", "hosted#scope", fmt.Sprintf("%s: hosted report state %s (unbound).", b.Repo, state),
		Subject{Module: b.Repo, Version: b.RequestedPin}, output, scopeDetails)
	if state == "downloaded" {
		tblID := addEvidence("hosted_package_table", "hosted#packages", fmt.Sprintf("%d hosted package row(s) recorded (unbound).", len(rows)),
			Subject{Module: b.Repo, Version: b.RequestedPin}, tableDigest, map[string]any{"table_artifact": tableDigest, "table_digest": tableDigest,
				"row_count": len(rows), "key": "spdx_id", "lane": "hosted_unbound"})
		claimStatus, expl := "supported", "Supported by hosted_sbom_scope evidence "+scopeID+": a downloaded report was recorded, unbound to the pinned commit."
		if len(unparsed) > 0 {
			claimStatus, expl = "unknown", "Some hosted packages could not be recorded; the hosted inventory is not asserted complete."
		}
		res.Claims = append(res.Claims, Claim{ClaimID: t.TaskID + ".cl1", Type: "hosted_inventory_recorded_unbound", Dimension: "inventory",
			Proposition: fmt.Sprintf("The hosted report for %s lists %d package(s); it is not bound to the pinned commit.", b.Repo, len(rows)),
			EvidenceIDs: []string{scopeID, tblID}, Status: claimStatus, Explanation: expl})
		if len(unparsed) > 0 {
			class := make([]string, 0, len(unparsed))
			for k, n := range unparsed {
				class = append(class, fmt.Sprintf("%s:%d", k, n))
			}
			sort.Strings(class)
			res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
				Reason: "invalid_response", Detail: b.Repo + ": unrecorded hosted packages " + strings.Join(class, ",")})
			return s.finishV2(res, tokens, "partial", fmt.Sprintf("Partial: %d hosted rows; some packages were not recorded.", len(rows)))
		}
		return s.finishV2(res, tokens, "complete", fmt.Sprintf("Complete: %d hosted rows recorded, unbound.", len(rows)))
	}
	reason, ok := failureReason[state]
	detail := b.Repo + ": hosted report state " + state
	if state == "unsupported_spdx_version" {
		reason, ok = "unsupported_spdx_version", true
	}
	if !ok {
		reason = "hosted_not_acquired"
		if state == "ready" && len(facts.History) > 0 {
			last := facts.History[len(facts.History)-1]
			detail += " (download host " + last.LocationHost + " not approved or not requested)"
		}
	}
	res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory", Reason: reason, Detail: detail})
	return s.finishV2(res, tokens, "partial", "Partial: the hosted report was not acquired ("+state+"); no inventory recorded.")
}

func nonNilRows(r []hostedRow) []hostedRow {
	if r == nil {
		return []hostedRow{}
	}
	return r
}
