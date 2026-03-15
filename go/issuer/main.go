package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	issuelog "github.com/mta-qr/demo/issuer/log"
	"github.com/mta-qr/demo/shared/checkpoint"
	"github.com/mta-qr/demo/shared/merkle"
	"github.com/mta-qr/demo/shared/signing"
	"github.com/mta-qr/demo/shared/payload"
	qrcode "github.com/skip2/go-qrcode"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" { return v }
	return def
}

var origin    = envOr("MTA_ORIGIN", "demo.mta-qr.example/go-issuer/v1")
var listenAddr = ":" + strings.TrimPrefix(envOr("MTA_PORT", "8081"), ":")

var issuerLog *issuelog.Log

func main() {
	// Instantiate issuer signer based on MTA_SIG_ALG env (default Ed25519).
	sigAlgStr := os.Getenv("MTA_SIG_ALG")
	var issuerSigner signing.Signer
	var err error
	switch sigAlgStr {
	case "ecdsa-p256", "4":
		issuerSigner, err = signing.NewECDSAP256()
		if err != nil {
			log.Fatalf("init ECDSA-P256 signer: %v", err)
		}
	case "mldsa44", "ml-dsa-44", "1":
		issuerSigner, err = signing.NewMLDSA44()
		if err != nil {
			log.Fatalf("init ML-DSA-44 signer: %v", err)
		}
	default: // Ed25519
		issuerSigner, err = signing.NewEd25519()
		if err != nil {
			log.Fatalf("init Ed25519 signer: %v", err)
		}
	}

	issuerLog, err = issuelog.New(origin, issuerSigner)
	if err != nil {
		log.Fatalf("init log: %v", err)
	}
	log.Printf("Go issuer started on %s", listenAddr)
	log.Printf("Origin: %s", origin)
	log.Printf("Sig alg: %s", signing.SigAlgName(issuerSigner.SigAlg()))
	log.Printf("Issuer pub key: %x", issuerLog.IssuerPublicKey())

	http.HandleFunc("/", handleUI)
	http.HandleFunc("/issue", handleIssue)
	http.HandleFunc("/checkpoint", handleCheckpoint)
	http.HandleFunc("/trust-config", handleTrustConfig)
	http.HandleFunc("/qr.png", handleQRPNG)

	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// --- API handlers ---

// handleCheckpoint serves the current cosigned checkpoint in tlog-checkpoint
// note format. Mode 1 verifiers fetch this on cache miss.
func handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	ckpt := issuerLog.LatestCheckpoint()
	if ckpt == nil {
		http.Error(w, "no checkpoint", http.StatusServiceUnavailable)
		return
	}

	// Assemble the full signed note: body + blank line + signature lines.
	note := string(ckpt.Body) + "\n"
	// Per c2sp.org/signed-note: sig payload = 4-byte keyhash || raw_signature.
	issuerKeyName := issuerLog.NoteKeyName()
	issuerKeyID := issuerLog.NoteKeyID()
	issuerPayload := append(issuerKeyID[:], ckpt.IssuerSig...)
	note += fmt.Sprintf("— %s %s\n", issuerKeyName, base64.StdEncoding.EncodeToString(issuerPayload))

	for i, cosig := range ckpt.Cosigs {
		w := issuerLog.Witnesses()[i]
		// Per c2sp.org/signed-note: sig line is "— <bare_name> <base64(4_keyhash || payload)>"
		// For tlog-cosignature: payload = 8-byte big-endian timestamp + 64-byte Ed25519 sig.
		// Total base64 payload = 4 + 8 + 64 = 76 bytes.
		keyID := checkpoint.KeyID(w.Name, w.PubKey)
		payload := make([]byte, 4+8+64)
		copy(payload[0:4], keyID[:])
		binary.BigEndian.PutUint64(payload[4:12], cosig.Timestamp)
		copy(payload[12:76], cosig.Signature[:])
		note += fmt.Sprintf("— %s %s\n", w.Name, base64.StdEncoding.EncodeToString(payload))
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, note)
}

// handleTrustConfig serves the trust configuration JSON that verifiers need.
func handleTrustConfig(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	tc := issuerLog.TrustConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tc)
}

// IssueRequest is the JSON body for POST /issue.
type IssueRequest struct {
	SchemaID   uint64         `json:"schema_id"`
	TTLSeconds uint64         `json:"ttl_seconds"`
	Claims     map[string]any `json:"claims"`
}

// IssueResponse is returned by POST /issue.
type IssueResponse struct {
	EntryIndex  uint64 `json:"entry_index"`
	PayloadHex  string `json:"payload_hex"`
	PayloadB64  string `json:"payload_b64"`
	QRPNGURL    string `json:"qr_png_url"`
	TreeSize    uint64 `json:"tree_size"`
	EntryHashHex string `json:"entry_hash_hex"`
}

func handleIssue(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	var req IssueRequest
	// Limit request body to prevent memory exhaustion from oversized payloads.
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
		return
	}
	if req.TTLSeconds == 0 {
		req.TTLSeconds = 3600
	}
	if req.Claims == nil {
		req.Claims = map[string]any{}
	}

	now := uint64(time.Now().Unix())
	expiry := now + req.TTLSeconds

	idx, payloadBytes, err := issuerLog.AppendDataAssertion(now, expiry, req.SchemaID, req.Claims)
	if err != nil {
		http.Error(w, fmt.Sprintf("issue error: %v", err), http.StatusInternalServerError)
		return
	}

	// Decode payload to get entry hash for display.
	p, _ := payload.Decode(payloadBytes)
	var entryHashHex string
	if p != nil {
		entryHashHex = hex.EncodeToString(merkle.EntryHash(p.TBS))
	}
	ckpt := issuerLog.LatestCheckpoint()

	resp := IssueResponse{
		EntryIndex:   idx,
		PayloadHex:   hex.EncodeToString(payloadBytes),
		PayloadB64:   base64.StdEncoding.EncodeToString(payloadBytes),
		QRPNGURL:     fmt.Sprintf("/qr.png?payload=%s", base64.URLEncoding.EncodeToString(payloadBytes)),
		TreeSize:     ckpt.TreeSize,
		EntryHashHex: entryHashHex,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleQRPNG renders a QR code PNG for a base64url-encoded payload.
func handleQRPNG(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	payloadB64 := r.URL.Query().Get("payload")
	if payloadB64 == "" {
		http.Error(w, "missing payload param", http.StatusBadRequest)
		return
	}
	payloadBytes, err := base64.URLEncoding.DecodeString(payloadB64)
	if err != nil {
		http.Error(w, "invalid base64", http.StatusBadRequest)
		return
	}

	size, _ := strconv.Atoi(r.URL.Query().Get("size"))
	if size == 0 {
		size = 400
	}
	// Cap size to prevent expensive large QR renders.
	if size > 2000 {
		size = 2000
	}

	png, err := qrcode.Encode(string(payloadBytes), qrcode.Medium, size)
	if err != nil {
		http.Error(w, fmt.Sprintf("qr encode: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

// handleUI serves the issuer demo web interface.
func handleUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	algName := signing.SigAlgName(issuerLog.TrustConfig().SigAlg)
	algVal := fmt.Sprintf("%d", issuerLog.TrustConfig().SigAlg)
	r2 := strings.NewReplacer("{{ALG_NAME}}", algName, "{{ALG_VAL}}", algVal)
	w.Write([]byte(r2.Replace(issuerHTML)))
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

const issuerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MTA-QR Go Issuer</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'SF Mono', 'Fira Code', monospace; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 16px; font-weight: 600; color: #f0f6fc; }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 12px; background: #388bfd22; color: #388bfd; border: 1px solid #388bfd44; }
  .badge.go { background: #00add822; color: #00add8; border-color: #00add844; }
  main { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 53px); }
  .panel { padding: 24px; border-right: 1px solid #30363d; overflow-y: auto; }
  .panel h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em; color: #8b949e; margin-bottom: 20px; }
  .field { margin-bottom: 16px; }
  label { display: block; font-size: 12px; color: #8b949e; margin-bottom: 6px; }
  input, textarea, select {
    width: 100%; background: #161b22; border: 1px solid #30363d; color: #c9d1d9;
    padding: 8px 12px; border-radius: 6px; font-family: inherit; font-size: 13px;
  }
  input:focus, textarea:focus { outline: none; border-color: #388bfd; }
  textarea { resize: vertical; min-height: 80px; }
  button {
    background: #238636; color: #fff; border: none; padding: 10px 20px;
    border-radius: 6px; font-family: inherit; font-size: 13px; cursor: pointer;
    width: 100%; font-weight: 600;
  }
  button:hover { background: #2ea043; }
  button:disabled { background: #21262d; color: #8b949e; cursor: not-allowed; }
  .result { display: none; margin-top: 24px; }
  .result.show { display: block; }
  .qr-wrap { text-align: center; margin-bottom: 20px; }
  .qr-wrap img { border: 4px solid #fff; border-radius: 4px; max-width: 280px; }
  .field-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .info-block { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; margin-bottom: 12px; }
  .info-block .kv { display: flex; gap: 8px; margin-bottom: 4px; font-size: 12px; }
  .info-block .k { color: #8b949e; flex-shrink: 0; }
  .info-block .v { color: #58a6ff; word-break: break-all; }
  .hex-block { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; font-size: 11px; color: #7ee787; word-break: break-all; max-height: 120px; overflow-y: auto; }
  .status { padding: 8px 12px; border-radius: 6px; font-size: 12px; margin-bottom: 12px; }
  .status.ok { background: #1f3d1f; color: #56d364; border: 1px solid #2ea04344; }
  .status.err { background: #3d1f1f; color: #f85149; border: 1px solid #f8514944; }
  .log-info { border-top: 1px solid #30363d; padding-top: 16px; margin-top: 16px; }
  .log-info .stat { font-size: 12px; color: #8b949e; margin-bottom: 4px; }
  .log-info .stat span { color: #c9d1d9; }
  .tabs { display: flex; gap: 1px; margin-bottom: 16px; border-bottom: 1px solid #30363d; }
  .tab { padding: 8px 16px; font-size: 12px; cursor: pointer; color: #8b949e; border-bottom: 2px solid transparent; margin-bottom: -1px; }
  .tab.active { color: #f0f6fc; border-bottom-color: #388bfd; }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  .examples { display: grid; gap: 8px; margin-bottom: 16px; }
  .example-btn { background: #161b22; border: 1px solid #30363d; color: #8b949e; padding: 8px 12px; border-radius: 6px; cursor: pointer; text-align: left; font-size: 12px; width: 100%; }
  .example-btn:hover { border-color: #58a6ff; color: #58a6ff; background: #161b22; }
</style>
</head>
<body>
<header>
  <h1>MTA-QR Demo</h1>
  <span class="badge go">Go Issuer</span>
  <span class="badge">{{ALG_NAME}} · Mode 1</span>
  <span class="badge" id="entry-count">0 entries</span>
</header>
<main>
  <div class="panel">
    <h2>Issue Assertion</h2>

    <div class="tabs">
      <div class="tab active" onclick="switchTab('form')">Form</div>
      <div class="tab" onclick="switchTab('examples')">Examples</div>
      <div class="tab" onclick="switchTab('raw')">Raw JSON</div>
    </div>

    <div class="tab-content active" id="tab-form">
      <div class="field">
        <label>Schema ID</label>
        <input type="number" id="schema-id" value="1" min="0">
      </div>
      <div class="field">
        <label>TTL (seconds)</label>
        <input type="number" id="ttl" value="3600" min="60">
      </div>
      <div class="field">
        <label>Claims (key=value pairs)</label>
        <div id="claims-fields">
          <div class="field-row" style="margin-bottom:8px">
            <input type="text" placeholder="key" class="claim-key">
            <input type="text" placeholder="value" class="claim-val">
          </div>
        </div>
        <button type="button" onclick="addClaimField()" style="background:#21262d;color:#8b949e;margin-top:4px;width:auto;padding:6px 12px">+ Add field</button>
      </div>
    </div>

    <div class="tab-content" id="tab-examples">
      <div class="examples">
        <button class="example-btn" onclick="loadExample('ticket')">🎫 Event Ticket — venue entry pass with seat assignment</button>
        <button class="example-btn" onclick="loadExample('prescription')">💊 Prescription — pharmacy dispensing authorization</button>
        <button class="example-btn" onclick="loadExample('badge')">🪪 Access Badge — building access with zone permissions</button>
        <button class="example-btn" onclick="loadExample('package')">📦 Package Label — supply chain provenance assertion</button>
        <button class="example-btn" onclick="loadExample('membership')">🔄 Rotating Membership — short-lived member credential</button>
      </div>
    </div>

    <div class="tab-content" id="tab-raw">
      <div class="field">
        <label>Raw JSON body (overrides form)</label>
        <textarea id="raw-json" rows="8" placeholder='{"schema_id": 1, "ttl_seconds": 3600, "claims": {"key": "value"}}'></textarea>
      </div>
    </div>

    <button id="issue-btn" onclick="issue()">Issue QR Code</button>

    <div class="log-info" id="log-info">
      <div class="stat">Origin: <span id="log-origin">loading...</span></div>
      <div class="stat">Entries: <span id="log-entries">-</span></div>
      <div class="stat">Issuer key: <span id="issuer-key">loading...</span></div>
    </div>
  </div>

  <div class="panel" id="result-panel">
    <h2>Result</h2>
    <div id="status-msg"></div>

    <div class="result" id="result">
      <div class="qr-wrap">
        <img id="qr-img" src="" alt="QR Code">
      </div>

      <div class="info-block">
        <div class="kv"><span class="k">Entry index:</span><span class="v" id="r-index">-</span></div>
        <div class="kv"><span class="k">Tree size:</span><span class="v" id="r-tree">-</span></div>
        <div class="kv"><span class="k">Mode:</span><span class="v">1 — Cached checkpoint</span></div>
        <div class="kv"><span class="k">Sig alg:</span><span class="v">{{ALG_NAME}} ({{ALG_VAL}})</span></div>
      </div>

      <h2 style="margin-bottom:12px">Payload (hex)</h2>
      <div class="hex-block" id="r-hex"></div>

      <h2 style="margin-top:16px;margin-bottom:12px">Payload (base64)</h2>
      <div class="hex-block" id="r-b64"></div>

      <h2 style="margin-top:16px;margin-bottom:12px">Verify with</h2>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <button onclick="openVerifier('go')" style="background:#21262d;color:#8b949e;border:1px solid #30363d;width:auto;padding:8px 16px">Go Verifier :8082</button>
        <button onclick="openVerifier('ts')" style="background:#21262d;color:#8b949e;border:1px solid #30363d;width:auto;padding:8px 16px">TS Verifier :3002</button>
      </div>
    </div>

    <div style="margin-top:24px">
      <h2 style="margin-bottom:12px">Current Checkpoint</h2>
      <div class="hex-block" id="checkpoint-display" style="color:#c9d1d9;white-space:pre-wrap;max-height:200px"></div>
    </div>
  </div>
</main>

<script>
let lastPayloadB64 = '';

const examples = {
  ticket: {schema_id: 1001, ttl_seconds: 86400, claims: {event: "MTA-QR Summit 2026", seat: "B-42", tier: "general"}},
  prescription: {schema_id: 1002, ttl_seconds: 604800, claims: {drug: "Amoxicillin 500mg", qty: "20", prescriber: "Dr. Smith", patient_id: "P-8821"}},
  badge: {schema_id: 1003, ttl_seconds: 28800, claims: {holder: "A. Example", zones: "A,B,C", valid_date: new Date().toISOString().split('T')[0]}},
  package: {schema_id: 1004, ttl_seconds: 2592000, claims: {sku: "PKG-00441", origin: "MFR-WA-01", batch: "2026-Q1-B"}},
  membership: {schema_id: 1005, ttl_seconds: 300, claims: {member_id: "M-" + Math.floor(Math.random()*99999), tier: "premium"}},
};

function loadExample(name) {
  const ex = examples[name];
  document.getElementById('schema-id').value = ex.schema_id;
  document.getElementById('ttl').value = ex.ttl_seconds;
  // Clear and fill claims
  const container = document.getElementById('claims-fields');
  container.innerHTML = '';
  for (const [k, v] of Object.entries(ex.claims)) {
    addClaimField(k, String(v));
  }
  switchTab('form');
}

function addClaimField(k='', v='') {
  const container = document.getElementById('claims-fields');
  const row = document.createElement('div');
  row.className = 'field-row';
  row.style.marginBottom = '8px';
  const ki = document.createElement('input'); ki.type='text'; ki.placeholder='key';   ki.className='claim-key'; ki.value=k;
  const vi = document.createElement('input'); vi.type='text'; vi.placeholder='value'; vi.className='claim-val'; vi.value=v;
  row.appendChild(ki); row.appendChild(vi);
  container.appendChild(row);
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => {
    const names = ['form','examples','raw'];
    t.classList.toggle('active', names[i] === name);
  });
  document.querySelectorAll('.tab-content').forEach(t => {
    t.classList.toggle('active', t.id === 'tab-'+name);
  });
}

async function issue() {
  const btn = document.getElementById('issue-btn');
  btn.disabled = true;
  btn.textContent = 'Issuing...';
  setStatus('', '');

  let body;
  const rawJSON = document.getElementById('raw-json').value.trim();
  if (rawJSON) {
    try { body = JSON.parse(rawJSON); }
    catch(e) { setStatus('err', 'Invalid JSON: ' + e.message); btn.disabled=false; btn.textContent='Issue QR Code'; return; }
  } else {
    const claims = {};
    document.querySelectorAll('.claim-key').forEach((k,i) => {
      const keys = document.querySelectorAll('.claim-key');
      const vals = document.querySelectorAll('.claim-val');
      if (keys[i].value.trim()) claims[keys[i].value.trim()] = vals[i].value.trim();
    });
    body = {
      schema_id: parseInt(document.getElementById('schema-id').value),
      ttl_seconds: parseInt(document.getElementById('ttl').value),
      claims,
    };
  }

  try {
    const resp = await fetch('/issue', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    const data = await resp.json();
    if (!resp.ok) { setStatus('err', data); btn.disabled=false; btn.textContent='Issue QR Code'; return; }

    lastPayloadB64 = data.payload_b64;
    document.getElementById('qr-img').src = data.qr_png_url;
    document.getElementById('r-index').textContent = data.entry_index;
    document.getElementById('r-tree').textContent = data.tree_size;
    document.getElementById('r-hex').textContent = data.payload_hex;
    document.getElementById('r-b64').textContent = data.payload_b64;
    document.getElementById('result').classList.add('show');
    setStatus('ok', 'Issued at entry index ' + data.entry_index + ' · tree size ' + data.tree_size);
    refreshStatus();
  } catch(e) {
    setStatus('err', 'Network error: ' + e.message);
  }
  btn.disabled=false; btn.textContent='Issue QR Code';
}

function setStatus(type, msg) {
  const el = document.getElementById('status-msg');
  if (!msg) { el.innerHTML=''; return; }
  el.innerHTML = '<div class="status '+type+'">'+msg+'</div>';
}

function openVerifier(impl) {
  const port = impl === 'go' ? '8082' : '3002';
  const url = 'http://localhost:' + port + '/?payload=' + encodeURIComponent(lastPayloadB64);
  window.open(url, '_blank');
}

async function refreshStatus() {
  try {
    const tc = await (await fetch('/trust-config')).json();
    document.getElementById('log-origin').textContent = tc.origin;
    document.getElementById('issuer-key').textContent = tc.issuer_pub_key_hex.slice(0,16)+'...';

    const ckpt = await (await fetch('/checkpoint')).text();
    document.getElementById('checkpoint-display').textContent = ckpt;
    document.getElementById('log-entries').textContent = ckpt.split('\n')[1] || '-';
    document.getElementById('entry-count').textContent = (ckpt.split('\n')[1] || '0') + ' entries';
  } catch(e) {}
}

// Initialize
addClaimField('subject', 'demo');
addClaimField('note', 'MTA-QR prototype');
refreshStatus();
setInterval(refreshStatus, 5000);
</script>
</body>
</html>`
