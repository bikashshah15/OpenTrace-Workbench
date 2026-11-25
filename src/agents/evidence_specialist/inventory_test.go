package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// repoRoot finds the repository root from the test's working directory.
func findRoot(t *testing.T) string {
	t.Helper()
	d, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(d, "evidence", "i3")); err == nil {
			return d
		}
		d = filepath.Dir(d)
	}
	t.Fatal("repository root not found")
	return ""
}

type capManifest struct {
	Captures []struct {
		Kind, URL, ResponseDigest string
	} `json:"captures"`
}

// sourceBlob reads a manifest blob of the committed real source capture set.
func sourceBlob(t *testing.T, repo, commitPrefix, path string) []byte {
	t.Helper()
	root := findRoot(t)
	dirs, _ := filepath.Glob(filepath.Join(root, "evidence", "i3", "captures", "*", "capture_manifest.json"))
	for _, m := range dirs {
		raw, _ := os.ReadFile(m)
		var man struct {
			Captures []struct {
				Kind           string `json:"kind"`
				URL            string `json:"url"`
				ResponseDigest string `json:"response_digest"`
			} `json:"captures"`
		}
		if json.Unmarshal(raw, &man) != nil {
			continue
		}
		for _, c := range man.Captures {
			marker := "github.com/" + repo + "/blob/"
			i := strings.Index(c.URL, marker)
			if i < 0 || (c.Kind != "source_blob" && c.Kind != "license_blob") {
				continue
			}
			rest := c.URL[i+len(marker):] // <commit>/<path>
			j := strings.Index(rest, "/")
			if j > 0 && strings.HasPrefix(rest[:j], commitPrefix) && rest[j+1:] == path {
				b, err := os.ReadFile(filepath.Join(filepath.Dir(m), "blobs", strings.TrimPrefix(c.ResponseDigest, "sha256:")))
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
		}
	}
	t.Fatalf("blob %s %s not in a committed source capture set", repo, path)
	return nil
}

type expectedFile struct {
	Path string   `json:"path"`
	Rows []expRow `json:"rows"`
}

type expRow struct {
	Locator         string  `json:"locator"`
	Ecosystem       string  `json:"ecosystem"`
	NameOriginal    string  `json:"name_original"`
	NameNormalized  string  `json:"name_normalized"`
	VersionOriginal *string `json:"version_original"`
	VersionState    string  `json:"version_state"`
	Direct          *bool   `json:"direct"`
	Scope           string  `json:"scope"`
}

func loadExpected(t *testing.T, file string) expectedFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(findRoot(t), "evidence", "fixtures", "i3", "expected", file))
	if err != nil {
		t.Fatal(err)
	}
	var e expectedFile
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func tupleOf(r occRow) expRow {
	return expRow{r.Locator, r.Ecosystem, r.NameOriginal, r.NameNormalized, r.VersionOriginal, r.VersionState, r.Direct, r.Scope}
}

func tupleKey(r expRow) string {
	b, _ := json.Marshal(r)
	return string(b)
}

// rowDiff returns the differences between produced rows and expected tuples (empty means set equality on every tuple).
func rowDiff(label string, got []occRow, want []expRow) []string {
	g, w := map[string]bool{}, map[string]bool{}
	for _, r := range got {
		g[tupleKey(tupleOf(r))] = true
	}
	for _, r := range want {
		w[tupleKey(r)] = true
	}
	var out []string
	if len(got) != len(want) || len(g) != len(w) {
		out = append(out, fmt.Sprintf("%s: %d rows (%d distinct), want %d (%d)", label, len(got), len(g), len(want), len(w)))
	}
	var missing, extra []string
	for k := range w {
		if !g[k] {
			missing = append(missing, k)
		}
	}
	for k := range g {
		if !w[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	for i := 0; i < len(missing) && i < 3; i++ {
		out = append(out, label+": expected row not produced: "+missing[i])
	}
	for i := 0; i < len(extra) && i < 3; i++ {
		out = append(out, label+": unexpected row produced: "+extra[i])
	}
	return out
}

func compareRows(t *testing.T, label string, got []occRow, want []expRow) {
	t.Helper()
	for _, p := range rowDiff(label, got, want) {
		t.Error(p)
	}
}

type realCase struct{ repo, prefix, path, expected string }

var realGo = []realCase{
	{"modelcontextprotocol/go-sdk", "7c486efa8223", "go.mod", "modelcontextprotocol_go-sdk__go.mod.rows.json"},
	{"modelcontextprotocol/go-sdk", "7c486efa8223", "examples/server/auth-middleware/go.mod", "modelcontextprotocol_go-sdk__examples_server_auth-middleware_go.mod.rows.json"},
	{"modelcontextprotocol/go-sdk", "7c486efa8223", "examples/server/rate-limiting/go.mod", "modelcontextprotocol_go-sdk__examples_server_rate-limiting_go.mod.rows.json"},
	{"mark3labs/mcp-go", "e1bd0abdfa84", "go.mod", "mark3labs_mcp-go__go.mod.rows.json"},
	{"mark3labs/mcp-go", "e1bd0abdfa84", "otel/go.mod", "mark3labs_mcp-go__otel_go.mod.rows.json"},
	{"modelcontextprotocol/registry", "11b7b0e274d5", "go.mod", "modelcontextprotocol_registry__go.mod.rows.json"},
	{"modelcontextprotocol/registry", "11b7b0e274d5", "deploy/go.mod", "modelcontextprotocol_registry__deploy_go.mod.rows.json"},
}

func TestOracleGoFullRows(t *testing.T) {
	for _, c := range realGo {
		res := parseGoMod(sourceBlob(t, c.repo, c.prefix, c.path), nil)
		if res.Status != "parsed" || len(res.Unparsed) != 0 {
			t.Errorf("%s %s: status %s unparsed %v", c.repo, c.path, res.Status, res.Unparsed)
		}
		compareRows(t, c.repo+" "+c.path, res.Rows, loadExpected(t, c.expected).Rows)
	}
}

func TestOracleNpmFullRows(t *testing.T) {
	cases := []realCase{
		{"modelcontextprotocol/inspector", "074b8108f340", "package-lock.json", "modelcontextprotocol_inspector__package-lock.json.rows.json"},
		{"modelcontextprotocol/inspector", "074b8108f340", "clients/web/package-lock.json", "modelcontextprotocol_inspector__clients_web_package-lock.json.rows.json"},
		{"modelcontextprotocol/inspector", "074b8108f340", "clients/cli/package-lock.json", "modelcontextprotocol_inspector__clients_cli_package-lock.json.rows.json"},
		{"modelcontextprotocol/inspector", "074b8108f340", "clients/launcher/package-lock.json", "modelcontextprotocol_inspector__clients_launcher_package-lock.json.rows.json"},
		{"modelcontextprotocol/inspector", "074b8108f340", "clients/tui/package-lock.json", "modelcontextprotocol_inspector__clients_tui_package-lock.json.rows.json"},
		{"modelcontextprotocol/inspector", "074b8108f340", "clients/mcpdo/package-lock.json", "modelcontextprotocol_inspector__clients_mcpdo_package-lock.json.rows.json"},
	}
	for _, c := range cases {
		res := parseNpmLock(sourceBlob(t, c.repo, c.prefix, c.path))
		if res.Status != "parsed" || len(res.Unparsed) != 0 {
			t.Errorf("%s: status %s unparsed %v", c.path, res.Status, res.Unparsed)
		}
		compareRows(t, c.path, res.Rows, loadExpected(t, c.expected).Rows)
	}
}

func TestOracleLocklessPackageJSON(t *testing.T) {
	res := parsePackageJSON(sourceBlob(t, "mark3labs/mcp-go", "e1bd0abdfa84", "www/package.json"))
	compareRows(t, "www/package.json", res.Rows, loadExpected(t, "mark3labs_mcp-go__www_package.json.rows.json").Rows)
}

func TestOraclePnpmFullRows(t *testing.T) {
	res := parsePnpmLock(sourceBlob(t, "modelcontextprotocol/typescript-sdk", "9bc40e903fde", "pnpm-lock.yaml"))
	if res.Status != "parsed" || len(res.Unparsed) != 0 {
		t.Errorf("status %s unparsed %v reason %s", res.Status, res.Unparsed, res.Reason)
	}
	compareRows(t, "pnpm-lock.yaml", res.Rows, loadExpected(t, "modelcontextprotocol_typescript-sdk__pnpm-lock.yaml.rows.json").Rows)
}

func TestOracleUvFullRows(t *testing.T) {
	res := parseUvLock(sourceBlob(t, "modelcontextprotocol/python-sdk", "754254c08fe1", "uv.lock"))
	if res.Status != "parsed" || len(res.Unparsed) != 0 {
		t.Errorf("status %s unparsed %v reason %s", res.Status, res.Unparsed, res.Reason)
	}
	compareRows(t, "uv.lock", res.Rows, loadExpected(t, "modelcontextprotocol_python-sdk__uv.lock.rows.json").Rows)
}
