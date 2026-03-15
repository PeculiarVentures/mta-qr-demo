package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mta-qr/demo/shared/checkpoint"
	"github.com/mta-qr/demo/verifier/verify"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// httpClient is used for all outbound requests.
// The 10-second timeout prevents goroutine leaks from slow or hanging issuers.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// maxBodyBytes caps response body reads to prevent memory exhaustion.
const maxBodyBytes = 64 * 1024

var v = verify.New()

func main() {
	addr := ":" + strings.TrimPrefix(envOr("MTA_PORT", "8082"), ":")
	log.Printf("Go verifier started on %s", addr)
	log.Printf("No trust anchors loaded — POST /load-trust-config or visit the UI")

	http.HandleFunc("/", handleUI)
	http.HandleFunc("/verify", handleVerify)
	http.HandleFunc("/load-trust-config", handleLoadTrustConfig)
	http.HandleFunc("/anchors", handleAnchors)

	// Auto-load trust configs from MTA_TRUST_CONFIG_URLS (Docker / compose).
	if urls := os.Getenv("MTA_TRUST_CONFIG_URLS"); urls != "" {
		go autoLoadAll(strings.Split(urls, ","))
	}

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func autoLoadAll(urls []string) {
	time.Sleep(3 * time.Second)
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		for attempt := 0; attempt < 10; attempt++ {
			resp, err := httpClient.Get(u)
			if err != nil {
				log.Printf("trust config %s attempt %d: %v", u, attempt+1, err)
				time.Sleep(2 * time.Second)
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
			resp.Body.Close()
			if err := loadTrustConfigFromBytes(body); err != nil {
				log.Printf("parse trust config %s: %v", u, err)
				time.Sleep(2 * time.Second)
				continue
			}
			log.Printf("Auto-loaded trust config from %s", u)
			break
		}
	}
}

// handleVerify verifies a base64 or hex payload.
func handleVerify(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		return
	}

	var payloadBytes []byte

	// Support GET with ?payload=<base64url> (from issuer UI deep links).
	if r.Method == http.MethodGet {
		b64 := r.URL.Query().Get("payload")
		if b64 == "" {
			http.Error(w, "missing payload param", http.StatusBadRequest)
			return
		}
		var err error
		payloadBytes, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			payloadBytes, err = base64.StdEncoding.DecodeString(b64)
		}
		if err != nil {
			http.Error(w, "invalid base64 payload", http.StatusBadRequest)
			return
		}
	} else {
		// POST: JSON body with { "payload_hex": "..." } or { "payload_b64": "..." }
		var req struct {
			PayloadHex string `json:"payload_hex"`
			PayloadB64 string `json:"payload_b64"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad JSON", http.StatusBadRequest)
			return
		}
		var err error
		if req.PayloadHex != "" {
			payloadBytes, err = hex.DecodeString(req.PayloadHex)
		} else {
			payloadBytes, err = base64.StdEncoding.DecodeString(req.PayloadB64)
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("decode error: %v", err), http.StatusBadRequest)
			return
		}
	}

	result := v.Verify(payloadBytes)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// trustConfigJSON is the shape of a /trust-config response.
type trustConfigJSON struct {
	Origin        string `json:"origin"`
	OriginID      string `json:"origin_id"`
	IssuerPubKey  string `json:"issuer_pub_key_hex"`
	IssuerKeyName string `json:"issuer_key_name"`
	SigAlg        uint8  `json:"sig_alg"`
	WitnessQuorum int    `json:"witness_quorum"`
	CheckpointURL string `json:"checkpoint_url"`
	Witnesses     []struct {
		Name   string `json:"name"`
		KeyID  string `json:"key_id_hex"`
		PubKey string `json:"pub_key_hex"`
	} `json:"witnesses"`
}

// loadTrustConfigFromBytes parses and registers a trust anchor from raw JSON.
func loadTrustConfigFromBytes(body []byte) error {
	var tc trustConfigJSON
	if err := json.Unmarshal(body, &tc); err != nil {
		return fmt.Errorf("parse trust-config: %w", err)
	}
	issuerPubBytes, err := hex.DecodeString(tc.IssuerPubKey)
	if err != nil {
		return fmt.Errorf("decode issuer pub key: %w", err)
	}
	originIDInt, err := strconv.ParseUint(tc.OriginID, 16, 64)
	if err != nil {
		originIDInt = checkpoint.OriginID(tc.Origin)
	}
	witnesses := make([]verify.WitnessEntry, len(tc.Witnesses))
	for i, wc := range tc.Witnesses {
		pubBytes, err := hex.DecodeString(wc.PubKey)
		if err != nil {
			return fmt.Errorf("decode witness[%d] pub key: %w", i, err)
		}
		kidBytes, _ := hex.DecodeString(wc.KeyID)
		var kid [4]byte
		copy(kid[:], kidBytes)
		witnesses[i] = verify.WitnessEntry{Name: wc.Name, KeyID: kid, PubKey: pubBytes}
	}
	if tc.WitnessQuorum < 1 {
		return fmt.Errorf("witness_quorum must be >= 1, got %d", tc.WitnessQuorum)
	}
	if tc.WitnessQuorum > len(witnesses) {
		return fmt.Errorf("witness_quorum (%d) exceeds witness count (%d)", tc.WitnessQuorum, len(witnesses))
	}
	if err := v.AddAnchor(&verify.TrustAnchor{
		Origin: tc.Origin, OriginID: originIDInt, IssuerPubKey: issuerPubBytes,
		IssuerKeyName: tc.IssuerKeyName,
		SigAlg: tc.SigAlg, WitnessQuorum: tc.WitnessQuorum,
		Witnesses: witnesses, CheckpointURL: tc.CheckpointURL,
	}); err != nil {
		return fmt.Errorf("add anchor: %w", err)
	}
	log.Printf("Loaded trust anchor: %s (origin_id=%016x)", tc.Origin, originIDInt)
	return nil
}

// handleLoadTrustConfig fetches and registers a trust config from an issuer.
func handleLoadTrustConfig(w http.ResponseWriter, r *http.Request) {
	// Do NOT set wildcard CORS — this endpoint mutates server state.
	// Only the same-origin verifier UI should call it. Setting "null" blocks
	// all cross-origin requests; the browser enforces same-origin by default
	// when no ACAO header is present, but explicit null is clearer.
	w.Header().Set("Access-Control-Allow-Origin", "null")
	if r.Method == http.MethodOptions {
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if r.Method == http.MethodGet {
		req.URL = r.URL.Query().Get("url")
	} else {
		json.NewDecoder(r.Body).Decode(&req)
	}
	if req.URL == "" {
		req.URL = "http://localhost:8081/trust-config"
	}
	// SSRF mitigation: only localhost targets are permitted.
	parsed, parseErr := url.Parse(req.URL)
	if parseErr != nil || !isLocalhost(parsed.Hostname()) {
		http.Error(w, "trust-config URL must target localhost", http.StatusBadRequest)
		return
	}
	resp, err := httpClient.Get(req.URL)
	if err != nil {
		http.Error(w, fmt.Sprintf("fetch %s: %v", req.URL, err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err := loadTrustConfigFromBytes(body); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// handleAnchors lists loaded trust anchors.
func handleAnchors(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	anchors := v.Anchors()
	out := make([]map[string]any, len(anchors))
	for i, a := range anchors {
		out[i] = map[string]any{
			"origin":         a.Origin,
			"origin_id":      fmt.Sprintf("%016x", a.OriginID),
			"sig_alg":        a.SigAlg,
			"witness_quorum": a.WitnessQuorum,
			"checkpoint_url": a.CheckpointURL,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func handleUI(w http.ResponseWriter, r *http.Request) {
	// If a payload is in the URL (deep link from issuer), pre-fill it.
	prefilledPayload := r.URL.Query().Get("payload")
	html := verifierHTML
	if prefilledPayload != "" {
		html = fmt.Sprintf(`<script>window.__PREFILLED_PAYLOAD__ = %q;</script>`+"\n", prefilledPayload) + html
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

const verifierHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MTA-QR Go Verifier</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'SF Mono', 'Fira Code', monospace; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 16px; font-weight: 600; color: #f0f6fc; }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 12px; }
  .badge.go { background: #00add822; color: #00add8; border: 1px solid #00add844; }
  .badge.info { background: #388bfd22; color: #388bfd; border: 1px solid #388bfd44; }
  main { display: grid; grid-template-columns: 400px 1fr; gap: 0; height: calc(100vh - 53px); }
  .panel { padding: 24px; border-right: 1px solid #30363d; overflow-y: auto; }
  .panel h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em; color: #8b949e; margin-bottom: 16px; }
  .field { margin-bottom: 16px; }
  label { display: block; font-size: 12px; color: #8b949e; margin-bottom: 6px; }
  input, textarea { width: 100%; background: #161b22; border: 1px solid #30363d; color: #c9d1d9; padding: 8px 12px; border-radius: 6px; font-family: inherit; font-size: 12px; }
  input:focus, textarea:focus { outline: none; border-color: #388bfd; }
  textarea { resize: vertical; }
  button { background: #1f6feb; color: #fff; border: none; padding: 10px 20px; border-radius: 6px; font-family: inherit; font-size: 13px; cursor: pointer; width: 100%; font-weight: 600; margin-bottom: 8px; }
  button:hover { background: #388bfd; }
  .btn-secondary { background: #21262d; color: #8b949e; border: 1px solid #30363d; }
  .btn-secondary:hover { background: #30363d; color: #c9d1d9; }
  .step { display: flex; gap: 10px; align-items: flex-start; padding: 10px 12px; border-radius: 6px; margin-bottom: 6px; font-size: 12px; border: 1px solid transparent; }
  .step.ok { background: #1f3d1f; border-color: #2ea04322; }
  .step.fail { background: #3d1f1f; border-color: #f8514922; }
  .step.pending { background: #1c2128; border-color: #30363d; }
  .step-icon { flex-shrink: 0; font-size: 14px; margin-top: 1px; }
  .step-name { font-weight: 600; color: #f0f6fc; margin-bottom: 2px; }
  .step-detail { color: #8b949e; line-height: 1.4; word-break: break-all; }
  .result-header { padding: 16px; border-radius: 8px; margin-bottom: 20px; text-align: center; }
  .result-header.valid { background: #1f3d1f; border: 1px solid #2ea04344; }
  .result-header.invalid { background: #3d1f1f; border: 1px solid #f8514944; }
  .result-header.pending { background: #1c2128; border: 1px solid #30363d; }
  .result-icon { font-size: 36px; margin-bottom: 8px; }
  .result-text { font-size: 18px; font-weight: 700; }
  .result-text.valid { color: #56d364; }
  .result-text.invalid { color: #f85149; }
  .claims-grid { display: grid; gap: 8px; }
  .claim-row { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 10px 12px; }
  .claim-key { font-size: 11px; color: #8b949e; margin-bottom: 2px; }
  .claim-val { font-size: 13px; color: #f0f6fc; }
  .anchor-item { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 10px 12px; margin-bottom: 8px; font-size: 12px; }
  .anchor-origin { color: #58a6ff; margin-bottom: 4px; font-weight: 600; }
  .anchor-detail { color: #8b949e; }
  .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 16px; }
  .meta-item { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 8px 10px; }
  .meta-label { font-size: 10px; color: #8b949e; margin-bottom: 2px; text-transform: uppercase; letter-spacing: 0.05em; }
  .meta-val { font-size: 12px; color: #c9d1d9; }
  .divider { border: none; border-top: 1px solid #30363d; margin: 16px 0; }
</style>
</head>
<body>
<header>
  <h1>MTA-QR Demo</h1>
  <span class="badge go">Go Verifier</span>
  <span class="badge info">Mode 1</span>
  <span class="badge info" id="anchor-count">0 anchors</span>
</header>
<main>
  <div class="panel">
    <h2>Trust Anchors</h2>
    <div class="field">
      <label>Load from issuer /trust-config URL</label>
      <input type="text" id="tc-url" value="http://localhost:8081/trust-config" placeholder="http://issuer/trust-config">
    </div>
    <button onclick="loadTrustConfig()">Load Trust Config</button>
    <button class="btn-secondary" onclick="loadTrustConfig('http://localhost:3001/trust-config')">Load TS Issuer (3001)</button>
    <div id="anchors-list" style="margin-top:16px"></div>

    <hr class="divider">

    <h2>Payload Input</h2>
    <div class="field">
      <label>Base64 or hex payload</label>
      <textarea id="payload-input" rows="5" placeholder="Paste base64 or hex payload from issuer..."></textarea>
    </div>
    <button onclick="verifyPayload()">Verify</button>
    <button class="btn-secondary" onclick="clearAll()">Clear</button>
  </div>

  <div class="panel" id="result-panel">
    <div id="result-header" class="result-header pending">
      <div class="result-icon">🔍</div>
      <div class="result-text">Awaiting payload</div>
    </div>

    <div id="meta-section" style="display:none">
      <div class="meta-grid">
        <div class="meta-item"><div class="meta-label">Entry Index</div><div class="meta-val" id="m-idx">-</div></div>
        <div class="meta-item"><div class="meta-label">Tree Size</div><div class="meta-val" id="m-tree">-</div></div>
        <div class="meta-item"><div class="meta-label">Schema ID</div><div class="meta-val" id="m-schema">-</div></div>
        <div class="meta-item"><div class="meta-label">Mode / Alg</div><div class="meta-val" id="m-mode">-</div></div>
      </div>
      <div class="meta-item" style="margin-bottom:16px">
        <div class="meta-label">Origin</div>
        <div class="meta-val" id="m-origin" style="word-break:break-all">-</div>
      </div>
    </div>

    <div id="claims-section" style="display:none;margin-bottom:20px">
      <h2 style="margin-bottom:12px">Claims</h2>
      <div class="claims-grid" id="claims-grid"></div>
    </div>

    <h2 style="margin-bottom:12px">Verification Trace</h2>
    <div id="steps-list"></div>
  </div>
</main>

<script>
async function loadTrustConfig(url) {
  const tcUrl = url || document.getElementById('tc-url').value.trim();
  try {
    const resp = await fetch('/load-trust-config?url=' + encodeURIComponent(tcUrl));
    const data = await resp.json();
    if (data.ok) {
      showToast('Loaded: ' + data.origin);
    } else {
      showToast('Error: ' + JSON.stringify(data));
    }
    refreshAnchors();
  } catch(e) {
    showToast('Failed: ' + e.message);
  }
}

async function refreshAnchors() {
  const anchors = await (await fetch('/anchors')).json();
  const el = document.getElementById('anchors-list');
  document.getElementById('anchor-count').textContent = anchors.length + ' anchor' + (anchors.length !== 1 ? 's' : '');
  if (anchors.length === 0) {
    el.innerHTML = '<div style="font-size:12px;color:#8b949e">No anchors loaded</div>';
    return;
  }
  el.innerHTML = '';
  anchors.forEach(a => {
    const item   = document.createElement('div'); item.className = 'anchor-item';
    const origin = document.createElement('div'); origin.className = 'anchor-origin';
    origin.textContent = a.origin;
    const detail = document.createElement('div'); detail.className = 'anchor-detail';
    detail.textContent = 'sig_alg=' + a.sig_alg + ' quorum=' + a.witness_quorum + ' ' + a.checkpoint_url;
    item.appendChild(origin); item.appendChild(detail);
    el.appendChild(item);
  });
}

async function verifyPayload() {
  let raw = document.getElementById('payload-input').value.trim();
  if (!raw) return;

  setResultPending();

  let body;
  // Detect hex vs base64.
  if (/^[0-9a-f]+$/i.test(raw) && raw.length % 2 === 0) {
    body = JSON.stringify({payload_hex: raw});
  } else {
    // Try base64url then standard.
    body = JSON.stringify({payload_b64: raw});
  }

  try {
    const resp = await fetch('/verify', {method:'POST', headers:{'Content-Type':'application/json'}, body});
    const result = await resp.json();
    renderResult(result);
  } catch(e) {
    renderError(e.message);
  }
}

function renderResult(r) {
  const header = document.getElementById('result-header');
  header.className = 'result-header ' + (r.valid ? 'valid' : 'invalid');
  header.innerHTML = r.valid
    ? '<div class="result-icon">✅</div><div class="result-text valid">VALID</div>'
    : '<div class="result-icon">❌</div><div class="result-text invalid">INVALID</div>';

  if (r.entry_index || r.tree_size) {
    document.getElementById('meta-section').style.display = 'block';
    document.getElementById('m-idx').textContent = r.entry_index || '-';
    document.getElementById('m-tree').textContent = r.tree_size || '-';
    document.getElementById('m-schema').textContent = r.schema_id || '-';
    document.getElementById('m-mode').textContent = 'mode=' + r.mode + ' alg=' + r.sig_alg;
    document.getElementById('m-origin').textContent = r.origin || '-';
  }

  if (r.claims && Object.keys(r.claims).length > 0) {
    document.getElementById('claims-section').style.display = 'block';
    const grid = document.getElementById('claims-grid');
    grid.innerHTML = '';
    Object.entries(r.claims).forEach(([k, v]) => {
      const row = document.createElement('div'); row.className = 'claim-row';
      const key = document.createElement('div'); key.className = 'claim-key'; key.textContent = k;
      const val = document.createElement('div'); val.className = 'claim-val'; val.textContent = v;
      row.appendChild(key); row.appendChild(val); grid.appendChild(row);
    });
  } else {
    document.getElementById('claims-section').style.display = 'none';
  }

  const stepsList = document.getElementById('steps-list');
  stepsList.innerHTML = '';
  (r.steps || []).forEach(s => {
    const step  = document.createElement('div'); step.className = 'step ' + (s.ok ? 'ok' : 'fail');
    const icon  = document.createElement('div'); icon.className = 'step-icon'; icon.textContent = s.ok ? '✓' : '✗';
    const body  = document.createElement('div');
    const name  = document.createElement('div'); name.className = 'step-name';  name.textContent = s.name;
    const dtail = document.createElement('div'); dtail.className = 'step-detail'; dtail.textContent = s.detail;
    body.appendChild(name); body.appendChild(dtail);
    step.appendChild(icon); step.appendChild(body);
    stepsList.appendChild(step);
  });
}

function setResultPending() {
  document.getElementById('result-header').className = 'result-header pending';
  document.getElementById('result-header').innerHTML = '<div class="result-icon">⏳</div><div class="result-text">Verifying...</div>';
  document.getElementById('steps-list').innerHTML = '';
  document.getElementById('meta-section').style.display = 'none';
  document.getElementById('claims-section').style.display = 'none';
}

function renderError(msg) {
  document.getElementById('result-header').className = 'result-header invalid';
  document.getElementById('result-header').innerHTML = '<div class="result-icon">❌</div><div class="result-text invalid">ERROR</div>';
  document.getElementById('steps-list').innerHTML = '<div class="step fail"><div class="step-icon">✗</div><div><div class="step-name">Network error</div><div class="step-detail">' + msg + '</div></div></div>';
}

function clearAll() {
  document.getElementById('payload-input').value = '';
  document.getElementById('result-header').className = 'result-header pending';
  document.getElementById('result-header').innerHTML = '<div class="result-icon">🔍</div><div class="result-text">Awaiting payload</div>';
  document.getElementById('steps-list').innerHTML = '';
  document.getElementById('meta-section').style.display = 'none';
  document.getElementById('claims-section').style.display = 'none';
}

function showToast(msg) {
  console.log(msg);
}

// Auto-load prefilled payload from deep link.
if (typeof window.__PREFILLED_PAYLOAD__ !== 'undefined') {
  document.getElementById('payload-input').value = window.__PREFILLED_PAYLOAD__;
  // Auto-load Go issuer trust config then verify.
  loadTrustConfig('http://localhost:8081/trust-config').then(() => {
    setTimeout(verifyPayload, 300);
  });
}

// Auto-load both issuers on startup.
Promise.all([
  fetch('/load-trust-config?url=http://localhost:8081/trust-config').catch(()=>{}),
  fetch('/load-trust-config?url=http://localhost:3001/trust-config').catch(()=>{}),
]).then(() => refreshAnchors());
</script>
</body>
</html>`
