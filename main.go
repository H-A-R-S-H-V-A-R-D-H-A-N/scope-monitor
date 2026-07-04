// scope-monitor watches HackerOne, Bugcrowd, and Intigriti program scope
// data (sourced from arkadiyt/bounty-targets-data, which crawls all three
// platforms every ~30 min) and pushes a Telegram alert whenever:
//   - a new program appears
//   - a program disappears (removed/renamed/taken private)
//   - a new in-scope target is added to an existing program
//   - an in-scope target is removed from an existing program
//
// A full-record hash is tracked per program but no longer triggers its own
// alert — it originally flagged any other change as "needs manual check",
// but in practice that fired on volatile stats fields (report counts,
// bounty averages, activity timestamps) with zero relation to scope.
// Confirmed false-positive prone, so only the four events above alert now.
//
// State is persisted to state.json and expected to be committed back to the
// repo by the CI workflow, so you also get a git history of every diff.
//
// NOTE ON FIELD NAMES: I could not fetch the live hackerone_data.json /
// bugcrowd_data.json directly (17MB+, GitHub won't preview it) to lock exact
// field names, so getField() below tries several candidate keys per logical
// field. If a program name/URL/asset shows up blank or wrong in your first
// Telegram alert, tell me which platform + which field and I'll fix the
// candidate list in one line.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	hackeroneURL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json"
	bugcrowdURL  = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json"
	intigritiURL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json"
	telegramMax  = 3900 // stay under Telegram's 4096 char limit with margin
)

type Asset struct {
	ID   string // asset_identifier / target
	Type string // asset_type / category (best effort)
}

type Program struct {
	Key      string // stable id we diff on
	Name     string
	URL      string
	InScope  map[string]Asset
	OutScope map[string]Asset
	Hash     string // sha256 of the raw record, catches non-scope changes
}

type Snapshot struct {
	CapturedAt string             `json:"captured_at"`
	Programs   map[string]Program `json:"programs"`
}

func main() {
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if botToken == "" || chatID == "" {
		log.Fatal("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set")
	}
	statePath := os.Getenv("STATE_FILE")
	if statePath == "" {
		statePath = "state.json"
	}

	h1Raw, err := fetchJSON(hackeroneURL)
	if err != nil {
		log.Fatalf("fetching hackerone data: %v", err)
	}
	bcRaw, err := fetchJSON(bugcrowdURL)
	if err != nil {
		log.Fatalf("fetching bugcrowd data: %v", err)
	}
	inRaw, err := fetchJSON(intigritiURL)
	if err != nil {
		log.Fatalf("fetching intigriti data: %v", err)
	}
	// YesWeHack and Federacy are intentionally never fetched — HackerOne,
	// Bugcrowd, and Intigriti only.

	current := Snapshot{
		CapturedAt: time.Now().UTC().Format(time.RFC3339),
		Programs:   map[string]Program{},
	}

	for _, rec := range h1Raw {
		p := parseProgram(rec,
			[]string{"handle"},
			[]string{"name"},
			[]string{"url"},
			[]string{"asset_identifier", "identifier", "asset"},
			[]string{"asset_type", "type"},
		)
		if p.Key == "" {
			continue
		}
		current.Programs["h1:"+p.Key] = p
	}

	for _, rec := range bcRaw {
		p := parseProgram(rec,
			[]string{"code", "name"},
			[]string{"name"},
			[]string{"url"},
			[]string{"target", "asset_identifier", "identifier"},
			[]string{"type", "category"},
		)
		if p.Key == "" {
			continue
		}
		current.Programs["bc:"+p.Key] = p
	}

	for _, rec := range inRaw {
		p := parseProgram(rec,
			[]string{"id", "handle", "name"},
			[]string{"name"},
			[]string{"url", "web_url", "webUrl"},
			[]string{"endpoint", "asset_identifier", "identifier"},
			[]string{"type", "asset_type"},
		)
		if p.Key == "" {
			continue
		}
		current.Programs["in:"+p.Key] = p
	}

	previous := loadSnapshot(statePath)

	msgs := diff(previous, current)

	if previous == nil {
		msgs = []string{fmt.Sprintf(
			"📡 Scope monitor baseline captured.\nHackerOne programs: %d\nBugcrowd programs: %d\nIntigriti programs: %d\nMonitoring starts now — you'll get alerts on new/removed programs and scope changes going forward.",
			countPrefix(current.Programs, "h1:"), countPrefix(current.Programs, "bc:"), countPrefix(current.Programs, "in:"),
		)}
	}

	for _, m := range msgs {
		if err := sendTelegram(botToken, chatID, m); err != nil {
			log.Printf("telegram send failed: %v", err)
		}
		time.Sleep(500 * time.Millisecond) // don't hammer the Bot API
	}

	saveSnapshot(statePath, current)

	if len(msgs) == 0 {
		log.Println("no changes detected")
	} else {
		log.Printf("sent %d alert message(s)", len(msgs))
	}
}

// ---- fetching ----

func fetchJSON(u string) ([]map[string]interface{}, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, u)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out []map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", u, err)
	}
	return out, nil
}

// ---- parsing ----

func getField(m map[string]interface{}, candidates []string) string {
	for _, k := range candidates {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func parseProgram(rec map[string]interface{}, keyKeys, nameKeys, urlKeys, assetIDKeys, assetTypeKeys []string) Program {
	p := Program{
		Key:      getField(rec, keyKeys),
		Name:     getField(rec, nameKeys),
		URL:      getField(rec, urlKeys),
		InScope:  map[string]Asset{},
		OutScope: map[string]Asset{},
	}
	if p.Key == "" {
		p.Key = p.Name // last resort
	}

	targets, _ := rec["targets"].(map[string]interface{})
	if targets != nil {
		if in, ok := targets["in_scope"].([]interface{}); ok {
			for _, item := range in {
				if im, ok := item.(map[string]interface{}); ok {
					id := getField(im, assetIDKeys)
					if id == "" {
						continue
					}
					p.InScope[id] = Asset{ID: id, Type: getField(im, assetTypeKeys)}
				}
			}
		}
		if out, ok := targets["out_of_scope"].([]interface{}); ok {
			for _, item := range out {
				if im, ok := item.(map[string]interface{}); ok {
					id := getField(im, assetIDKeys)
					if id == "" {
						continue
					}
					p.OutScope[id] = Asset{ID: id, Type: getField(im, assetTypeKeys)}
				}
			}
		}
	}

	// Stable hash of the whole raw record (map keys are sorted by
	// encoding/json automatically) to catch changes we didn't parse
	// explicitly — policy text, severity tables, bounty toggles, etc.
	b, _ := json.Marshal(rec)
	sum := sha256.Sum256(b)
	p.Hash = fmt.Sprintf("%x", sum)

	return p
}

func countPrefix(m map[string]Program, prefix string) int {
	n := 0
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// ---- diffing ----

func diff(prev *Snapshot, cur Snapshot) []string {
	var lines []string

	platformName := func(key string) string {
		switch {
		case strings.HasPrefix(key, "h1:"):
			return "HackerOne"
		case strings.HasPrefix(key, "in:"):
			return "Intigriti"
		default:
			return "Bugcrowd"
		}
	}

	if prev == nil {
		return nil // baseline run, handled by caller
	}

	var newProgramKeys, removedProgramKeys []string
	for k := range cur.Programs {
		if _, ok := prev.Programs[k]; !ok {
			newProgramKeys = append(newProgramKeys, k)
		}
	}
	for k := range prev.Programs {
		if _, ok := cur.Programs[k]; !ok {
			removedProgramKeys = append(removedProgramKeys, k)
		}
	}
	sort.Strings(newProgramKeys)
	sort.Strings(removedProgramKeys)

	for _, k := range newProgramKeys {
		p := cur.Programs[k]
		lines = append(lines, fmt.Sprintf("🆕 NEW PROGRAM [%s]\n%s\n%s\nIn-scope targets: %d",
			platformName(k), safeName(p), p.URL, len(p.InScope)))
	}
	for _, k := range removedProgramKeys {
		p := prev.Programs[k]
		lines = append(lines, fmt.Sprintf("❌ PROGRAM GONE (removed/renamed/private) [%s]\n%s\n%s",
			platformName(k), safeName(p), p.URL))
	}

	var changedKeys []string
	for k := range cur.Programs {
		if _, existedBefore := prev.Programs[k]; existedBefore {
			changedKeys = append(changedKeys, k)
		}
	}
	sort.Strings(changedKeys)

	for _, k := range changedKeys {
		p, cok := cur.Programs[k]
		pv, pok := prev.Programs[k]
		if !cok || !pok {
			continue
		}
		if p.Hash == pv.Hash {
			continue // nothing changed at all
		}

		var addedScope, removedScope []string
		for id := range p.InScope {
			if _, ok := pv.InScope[id]; !ok {
				addedScope = append(addedScope, id)
			}
		}
		for id := range pv.InScope {
			if _, ok := p.InScope[id]; !ok {
				removedScope = append(removedScope, id)
			}
		}
		sort.Strings(addedScope)
		sort.Strings(removedScope)

		if len(addedScope) == 0 && len(removedScope) == 0 {
			// Hash changed but no scope-item diff detected. This used to
			// fire an "UPDATED (non-scope change)" alert, but in practice
			// it triggered on volatile stats fields (report counts, bounty
			// averages, last-activity timestamps) on big active programs
			// that change constantly with zero relation to scope. Confirmed
			// false-positive prone, so it's silently skipped now rather
			// than alerting on noise.
			continue
		}

		var b strings.Builder
		fmt.Fprintf(&b, "🎯 SCOPE CHANGE [%s]\n%s\n%s\n", platformName(k), safeName(p), p.URL)
		if len(addedScope) > 0 {
			fmt.Fprintf(&b, "+ Added (%d):\n", len(addedScope))
			for _, id := range addedScope {
				fmt.Fprintf(&b, "  + %s\n", id)
			}
		}
		if len(removedScope) > 0 {
			fmt.Fprintf(&b, "- Removed (%d):\n", len(removedScope))
			for _, id := range removedScope {
				fmt.Fprintf(&b, "  - %s\n", id)
			}
		}
		lines = append(lines, strings.TrimRight(b.String(), "\n"))
	}

	return chunk(lines, telegramMax)
}

func safeName(p Program) string {
	if p.Name != "" {
		return p.Name
	}
	return p.Key
}

// chunk packs alert lines into Telegram-sized messages so we don't blow the
// 4096 char limit on a big diff, while keeping related lines together.
func chunk(lines []string, max int) []string {
	if len(lines) == 0 {
		return nil
	}
	var out []string
	var cur strings.Builder
	for _, l := range lines {
		if cur.Len()+len(l)+2 > max && cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteString("\n\n")
		}
		cur.WriteString(l)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// ---- state persistence ----

func loadSnapshot(path string) *Snapshot {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil // no previous state -> first run
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		log.Printf("warning: could not parse existing state file, treating as first run: %v", err)
		return nil
	}
	return &s
}

func saveSnapshot(path string, s Snapshot) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		log.Fatalf("marshal snapshot: %v", err)
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		log.Fatalf("write snapshot: %v", err)
	}
}

// redact strips any occurrence of a secret value out of an error string
// before it's logged, so it can never end up in this (public) repo's
// Actions run logs even if an HTTP client wraps the full request URL into
// its error message.
func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "[REDACTED]")
}

func sendTelegram(botToken, chatID, text string) error {
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	form := url.Values{}
	form.Set("chat_id", chatID)
	form.Set("text", text)
	form.Set("disable_web_page_preview", "true")

	resp, err := http.PostForm(endpoint, form)
	if err != nil {
		// Don't let the bot token leak into (public repo) Actions logs via
		// a wrapped URL error — Telegram's API puts the token in the URL,
		// and Go's http client embeds the full URL in connection errors.
		return fmt.Errorf("%s", redact(err.Error(), botToken))
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
