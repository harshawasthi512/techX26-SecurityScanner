class WaySecretsScanner {
    constructor() {
        this.apiBaseUrl = 'http://localhost:8000/api/waysecrets';
        this.wsBaseUrl = 'ws://localhost:8000/ws/waysecrets';
        this.currentScanId = null;
        this.ws = null;
        this.isScanning = false;
        this.scanResults = null;
        this.chart = null;
        
        this.init();
    }
    
    init() {
        this.initUI();
        this.initChart();
        this.checkConnection();
        setInterval(() => this.updateTime(), 1000);
    }
    
    initUI() {
        document.getElementById('start-scan-btn').addEventListener('click', () => this.startScan());
        
        document.querySelectorAll('.ws-tab').forEach(tab => {
            tab.addEventListener('click', (e) => this.switchTab(e.target));
        });
        
        document.getElementById('clear-logs').addEventListener('click', () => this.clearLogs());
        document.getElementById('copy-urls').addEventListener('click', () => this.copyURLs());
        document.getElementById('export-urls').addEventListener('click', () => this.exportURLs());
        
        document.getElementById('domain-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.startScan();
        });
    }
    
    initChart() {
        const ctx = document.getElementById('findings-chart').getContext('2d');
        this.chart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Severe', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#ff3860', '#ffd166', '#00bbf9', '#00ff88'],
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'right' } },
                cutout: '70%'
            }
        });
    }
    
    async checkConnection() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/stats`);
            if (response.ok) {
                this.setStatus('Connected', '#00ff88');
                this.addLog('Backend connected');
            } else {
                this.setStatus('Error', '#ff3860');
            }
        } catch {
            this.setStatus('Disconnected', '#ff3860');
        }
    }
    
    async startScan() {
        const domain = document.getElementById('domain-input').value.trim();
        if (!domain) {
            this.showToast('Enter a domain name', 'error');
            return;
        }
        
        // Reset UI
        this.resetUI();
        this.isScanning = true;
        this.setStatus('Scanning...', '#8a2be2');
        this.addLog(`Starting scan for: ${domain}`);
        
        // Disable scan button
        const scanBtn = document.getElementById('start-scan-btn');
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Scanning...</span>';
        
        try {
            // Start scan
            const response = await fetch(`${this.apiBaseUrl}/scan?domain=${encodeURIComponent(domain)}`, {
                method: 'POST'
            });
            
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const data = await response.json();
            this.currentScanId = data.scan_id;
            this.addLog(`Scan ID: ${this.currentScanId}`);
            
            // Connect WebSocket
            this.connectWebSocket();
            
        } catch (error) {
            this.addLog(`Failed: ${error.message}`);
            this.showToast('Failed to start scan', 'error');
            this.scanComplete(false);
        }
    }
    
    connectWebSocket() {
        if (this.ws) this.ws.close();
        
        this.ws = new WebSocket(`${this.wsBaseUrl}/${this.currentScanId}`);
        
        this.ws.onopen = () => {
            this.addLog('Connected to real-time updates');
        };
        
        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            } catch (e) {
                console.error('Parse error:', e);
            }
        };
        
        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.addLog('Connection error');
        };
        
        this.ws.onclose = () => {
            if (this.isScanning) {
                this.addLog('Connection closed');
                // Try to get results anyway
                setTimeout(() => this.getResults(), 1000);
            }
        };
    }
    
    handleMessage(data) {
        console.log('WebSocket message:', data);
        
        if (data.type === 'connected') {
            this.addLog('WebSocket connected');
            return;
        }
        
        if (data.type === 'progress') {
            // Update progress
            if (data.progress !== undefined) {
                this.updateProgress(data.progress);
            }
            
            // Add log
            if (data.message) {
                this.addLog(data.message);
                
                // Check for completion
                if (data.message.includes('✅') || data.message.includes('complete') || data.message.includes('Complete')) {
                    if (data.data) {
                        this.handleResults(data.data);
                    } else {
                        // If no data in message, fetch it
                        setTimeout(() => this.getResults(), 1000);
                    }
                }
            }
            
            // Handle results if in data
            if (data.data && data.data.phase === 'completed') {
                this.handleResults(data.data);
            }
        }
    }
    
    async getResults() {
        if (!this.currentScanId) return;
        
        try {
            const response = await fetch(`${this.apiBaseUrl}/scan/${this.currentScanId}`);
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'completed') {
                    this.handleResults({
                        results: typeof data.findings === 'string' ? JSON.parse(data.findings) : data.findings,
                        stats: typeof data.stats === 'string' ? JSON.parse(data.stats) : data.stats
                    });
                }
            }
        } catch (error) {
            console.error('Failed to get results:', error);
        }
    }
    
    handleResults(data) {
        if (!data || !data.results) {
            this.addLog('No results data');
            this.scanComplete(false);
            return;
        }
        
        this.scanResults = data;
        this.updateUI(data);
        this.scanComplete(true);
        this.showToast('Scan completed!', 'success');
    }
    
    updateUI(data) {
        const results = data.results;
        const stats = data.stats || {};
        
        // Update counters
        document.getElementById('urls-count').textContent = stats.urls_scanned || 0;
        document.getElementById('scan-time').textContent = `${stats.scan_duration || 0}s`;
        
        const totalFindings = 
            (results.sensitive_tokens?.length || 0) +
            (results.sensitive_endpoints?.length || 0) +
            (results.idor_params?.length || 0) +
            (results.open_redirect_params?.length || 0);
        
        document.getElementById('findings-count').textContent = totalFindings;
        
        // Update tab badges
        document.getElementById('tokens-badge').textContent = results.sensitive_tokens?.length || 0;
        document.getElementById('endpoints-badge').textContent = results.sensitive_endpoints?.length || 0;
        document.getElementById('idor-badge').textContent = results.idor_params?.length || 0;
        document.getElementById('redirects-badge').textContent = results.open_redirect_params?.length || 0;
        
        // Display findings
        this.displayFindings(results);
        
        // Display URLs
        this.displayURLs(results.sample_urls || []);
        
        // Update progress to 100%
        this.updateProgress(100);
    }
    
    displayFindings(results) {
        this.displaySection('tokens-list', results.sensitive_tokens || [], this.createTokenElement);
        this.displaySection('endpoints-list', results.sensitive_endpoints || [], this.createEndpointElement);
        this.displaySection('idor-list', results.idor_params || [], this.createIDORElement);
        this.displaySection('redirects-list', results.open_redirect_params || [], this.createRedirectElement);
    }
    
    displaySection(containerId, items, createElement) {
        const container = document.getElementById(containerId);
        
        if (!items || items.length === 0) {
            container.innerHTML = `
                <div class="ws-no-findings">
                    <i class="fas fa-check-circle"></i>
                    <span>No findings</span>
                </div>
            `;
            return;
        }
        
        container.innerHTML = '';
        items.forEach(item => {
            container.appendChild(createElement.call(this, item));
        });
    }
    
    createTokenElement(token) {
        const div = document.createElement('div');
        div.className = 'ws-finding-item';
        div.innerHTML = `
            <div class="ws-finding-header">
                <div class="ws-finding-title">${this.formatType(token.type)}</div>
                <div class="ws-finding-badge ${token.confidence || 'medium'}">
                    ${(token.confidence || 'Medium').charAt(0).toUpperCase() + (token.confidence || 'Medium').slice(1)}
                </div>
            </div>
            <div class="ws-finding-content">
                ${this.escape(token.token || token.full_match || 'N/A')}
            </div>
            <div class="ws-finding-url">
                URL: <a href="${this.escape(token.url)}" target="_blank">${this.truncate(token.url, 60)}</a>
            </div>
        `;
        return div;
    }
    
    createEndpointElement(endpoint) {
        const div = document.createElement('div');
        div.className = 'ws-finding-item';
        div.innerHTML = `
            <div class="ws-finding-header">
                <div class="ws-finding-title">${endpoint.label || 'Endpoint'}</div>
                <div class="ws-finding-badge high">High</div>
            </div>
            <div class="ws-finding-content">
                Path: ${this.escape(endpoint.path || 'N/A')}
            </div>
            <div class="ws-finding-url">
                URL: <a href="${this.escape(endpoint.url)}" target="_blank">${this.truncate(endpoint.url, 60)}</a>
            </div>
        `;
        return div;
    }
    
    createIDORElement(param) {
        const div = document.createElement('div');
        div.className = 'ws-finding-item';
        div.innerHTML = `
            <div class="ws-finding-header">
                <div class="ws-finding-title">IDOR: ${param.param}</div>
                <div class="ws-finding-badge ${param.confidence || 'medium'}">
                    ${(param.confidence || 'Medium').charAt(0).toUpperCase() + (param.confidence || 'Medium').slice(1)}
                </div>
            </div>
            <div class="ws-finding-content">
                ${param.param} = "${param.value}"
            </div>
            <div class="ws-finding-url">
                URL: <a href="${this.escape(param.url)}" target="_blank">${this.truncate(param.url, 60)}</a>
            </div>
        `;
        return div;
    }
    
    createRedirectElement(redirect) {
        const div = document.createElement('div');
        div.className = 'ws-finding-item';
        div.innerHTML = `
            <div class="ws-finding-header">
                <div class="ws-finding-title">Redirect: ${redirect.param}</div>
                <div class="ws-finding-badge ${redirect.confidence || 'medium'}">
                    ${(redirect.confidence || 'Medium').charAt(0).toUpperCase() + (redirect.confidence || 'Medium').slice(1)}
                </div>
            </div>
            <div class="ws-finding-content">
                ${redirect.param} = "${redirect.value}"
            </div>
            <div class="ws-finding-url">
                URL: <a href="${this.escape(redirect.url)}" target="_blank">${this.truncate(redirect.url, 60)}</a>
            </div>
        `;
        return div;
    }
    
    displayURLs(urls) {
        const container = document.getElementById('urls-list');
        
        if (!urls || urls.length === 0) {
            container.innerHTML = `
                <div class="ws-no-urls">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span>No URLs</span>
                </div>
            `;
            return;
        }
        
        container.innerHTML = '';
        urls.slice(0, 50).forEach(url => {
            const div = document.createElement('div');
            div.className = 'ws-url-item';
            div.textContent = url;
            container.appendChild(div);
        });
        
        if (urls.length > 50) {
            const more = document.createElement('div');
            more.className = 'ws-url-more';
            more.textContent = `... and ${urls.length - 50} more`;
            container.appendChild(more);
        }
    }
    
    updateProgress(percent) {
    const fill = document.getElementById('progress-fill');
    if (fill) {
        fill.style.height = `${percent}%`;
        
        // Update steps
        const steps = document.querySelectorAll('.ws-progress-step');
        steps.forEach((step, i) => {
            step.classList.remove('active', 'completed');
            if (percent >= (i + 1) * 25) step.classList.add('completed');
            else if (percent >= i * 25) step.classList.add('active');
        });
    }
    
    // Update mobile progress text
    const mobileText = document.getElementById('mobile-progress-text');
    if (mobileText) {
        mobileText.textContent = `${Math.round(percent)}%`;
    }
}
    
    scanComplete(success) {
        this.isScanning = false;
        
        // Re-enable scan button
        const scanBtn = document.getElementById('start-scan-btn');
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<i class="fas fa-play"></i><span>Start Scan</span>';
        
        // Update status
        if (success) {
            this.setStatus('Ready', '#00ff88');
        } else {
            this.setStatus('Error', '#ff3860');
        }
        
        // Close WebSocket
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
    
    resetUI() {
        // Reset counters
        ['urls-count', 'scan-time', 'findings-count', 'severe-count', 'high-count', 'medium-count', 'low-count'].forEach(id => {
            document.getElementById(id).textContent = '0';
        });
        
        // Reset badges
        ['tokens-badge', 'endpoints-badge', 'idor-badge', 'redirects-badge'].forEach(id => {
            document.getElementById(id).textContent = '0';
        });
        
        // Clear containers
        ['tokens-list', 'endpoints-list', 'idor-list', 'redirects-list', 'urls-list'].forEach(id => {
            document.getElementById(id).innerHTML = '';
        });
        
        // Reset progress
        this.updateProgress(0);
        
        // Reset chart
        if (this.chart) {
            this.chart.data.datasets[0].data = [0, 0, 0, 0];
            this.chart.update();
        }
    }
    
    // Helper methods
    addLog(message) {
        const logs = document.getElementById('scan-logs');
        const time = new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.className = 'ws-log-entry';
        entry.innerHTML = `<span class="ws-log-time">[${time}]</span> <span class="ws-log-message">${this.escape(message)}</span>`;
        logs.appendChild(entry);
        logs.scrollTop = logs.scrollHeight;
        
        // Keep only last 50 logs
        const entries = logs.querySelectorAll('.ws-log-entry');
        if (entries.length > 50) entries[0].remove();
    }
    
    clearLogs() {
        document.getElementById('scan-logs').innerHTML = `
            <div class="ws-log-entry">
                <span class="ws-log-time">[${new Date().toLocaleTimeString()}]</span>
                <span class="ws-log-message">Logs cleared</span>
            </div>
        `;
    }
    
    async copyURLs() {
        if (!this.scanResults?.results?.sample_urls?.length) {
            this.showToast('No URLs to copy', 'warning');
            return;
        }
        
        try {
            await navigator.clipboard.writeText(this.scanResults.results.sample_urls.join('\n'));
            this.showToast('URLs copied', 'success');
        } catch {
            this.showToast('Copy failed', 'error');
        }
    }
    
    exportURLs() {
        if (!this.scanResults?.results?.sample_urls?.length) {
            this.showToast('No URLs to export', 'warning');
            return;
        }
        
        const urls = this.scanResults.results.sample_urls;
        const blob = new Blob([urls.join('\n')], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `waysecrets-urls-${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        this.showToast('URLs exported', 'success');
    }
    
    switchTab(tab) {
        document.querySelectorAll('.ws-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.ws-findings-tab').forEach(t => t.classList.remove('active'));
        
        tab.classList.add('active');
        const tabId = tab.getAttribute('data-tab');
        document.getElementById(`${tabId}-tab`).classList.add('active');
    }
    
    showToast(message, type) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `ws-toast ${type}`;
        
        const icons = {
            success: 'fas fa-check-circle',
            error: 'fas fa-times-circle',
            warning: 'fas fa-exclamation-triangle',
            info: 'fas fa-info-circle'
        };
        
        toast.innerHTML = `
            <div class="ws-toast-header">
                <i class="${icons[type]}"></i>
                <span>${type.toUpperCase()}</span>
                <button onclick="this.parentElement.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div>${this.escape(message)}</div>
        `;
        
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 5000);
    }
    
    setStatus(text, color) {
        const dot = document.querySelector('.ws-status-dot');
        const textEl = document.querySelector('.ws-status-text');
        
        textEl.textContent = text;
        textEl.style.color = color;
        dot.style.background = color;
        dot.style.boxShadow = `0 0 10px ${color}`;
    }
    
    updateTime() {
        const now = new Date().toLocaleTimeString();
        const el = document.getElementById('current-time');
        if (el) el.textContent = now;
    }
    
    escape(text) {
        return text.toString()
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
    
    truncate(text, length) {
        if (!text) return 'N/A';
        return text.length > length ? text.substring(0, length) + '...' : text;
    }
    
    formatType(type) {
        if (!type) return 'Unknown';
        return type.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    new WaySecretsScanner();
});