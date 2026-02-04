// Configuration
const API_BASE_URL = 'http://127.0.0.1:8000';
let currentScanId = null;
let activeWebSocket = null;
let soundEnabled = true;
let notifications = [];
let currentResults = {};

// DOM Elements
const elements = {
    // Navigation
    navItems: document.querySelectorAll('.nav-item'),
    contentSections: document.querySelectorAll('.content-section'),
    pageTitle: document.getElementById('pageTitle'),
    
    // Dashboard
    startScanBtn: document.getElementById('startScanBtn'),
    totalScans: document.getElementById('totalScans'),
    secretsFound: document.getElementById('secretsFound'),
    bucketsFound: document.getElementById('bucketsFound'),
    vulnerableBuckets: document.getElementById('vulnerableBuckets'),
    recentScansTable: document.getElementById('recentScansTable'),
    
    // Scan Form
    scanForm: document.getElementById('scanForm'),
    orgName: document.getElementById('orgName'),
    scanType: document.getElementById('scanType'),
    includeBuckets: document.getElementById('includeBuckets'),
    resetForm: document.getElementById('resetForm'),
    
    // Active Scans
    activeScansCard: document.getElementById('activeScansCard'),
    activeScansContainer: document.getElementById('activeScansContainer'),
    
    // Results
    scanResultsCard: document.getElementById('scanResultsCard'),
    scanSummary: document.getElementById('scanSummary'),
    copyResultsBtn: document.getElementById('copyResultsBtn'),
    
    // Tabs
    tabButtons: document.querySelectorAll('.tab-btn'),
    tabContents: document.querySelectorAll('.tab-content'),
    
    // Tables
    secretsTable: document.getElementById('secretsTable'),
    bucketsTable: document.getElementById('bucketsTable'),
    
    // Filters
    severityButtons: document.querySelectorAll('.severity-btn'),
    
    // History
    historySearch: document.getElementById('historySearch'),
    historyStatusFilter: document.getElementById('historyStatusFilter'),
    historyTable: document.getElementById('historyTable'),
    deleteAllHistoryBtn: document.getElementById('deleteAllHistoryBtn'),
    
    // Patterns
    secretPatternsGrid: document.getElementById('secretPatternsGrid'),
    bucketPatternsGrid: document.getElementById('bucketPatternsGrid'),
    
    // Connection
    connectionStatus: document.getElementById('connectionStatus'),
    
    // Notifications
    notificationsBtn: document.getElementById('notificationsBtn'),
    notificationBadge: document.getElementById('notificationBadge'),
    notificationsPanel: document.getElementById('notificationsPanel'),
    clearNotificationsBtn: document.getElementById('clearNotificationsBtn'),
    notificationsList: document.getElementById('notificationsList'),
    
    // Sound
    soundToggle: document.getElementById('soundToggle'),
    beepSound: document.getElementById('beepSound'),
    
    // Modals
    detailModal: document.getElementById('detailModal'),
    modalTitle: document.getElementById('modalTitle'),
    modalBody: document.getElementById('modalBody'),
    confirmModal: document.getElementById('confirmModal'),
    confirmMessage: document.getElementById('confirmMessage'),
    confirmCancel: document.getElementById('confirmCancel'),
    confirmOk: document.getElementById('confirmOk'),
    
    // Toast
    toast: document.getElementById('toast'),
    toastMessage: document.getElementById('toastMessage')
};

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    initEventListeners();
    checkConnection();
    loadDashboardStats();
    loadRecentScans();
    loadDetectionPatterns();
    
    // Set default form values
    elements.scanType.value = 'public';
    elements.includeBuckets.checked = true;
});

// Event Listeners
function initEventListeners() {
    // Navigation
    elements.navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const tab = item.dataset.tab;
            switchTab(tab);
        });
    });
    
    // Dashboard scan button
    elements.startScanBtn?.addEventListener('click', () => {
        switchTab('scan');
    });
    
    // Scan form
    elements.scanForm?.addEventListener('submit', handleScanSubmit);
    elements.resetForm?.addEventListener('click', resetScanForm);
    
    // Results tabs
    elements.tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tab = button.dataset.tab;
            switchResultsTab(tab);
        });
    });
    
    // Severity filters
    elements.severityButtons?.forEach(button => {
        button.addEventListener('click', () => {
            const severity = button.dataset.severity;
            filterSecretsBySeverity(severity);
            elements.severityButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
        });
    });
    
    // Copy results
    elements.copyResultsBtn?.addEventListener('click', copyResultsToClipboard);
    
    // History
    elements.historySearch?.addEventListener('input', filterHistory);
    elements.historyStatusFilter?.addEventListener('change', filterHistory);
    elements.deleteAllHistoryBtn?.addEventListener('click', confirmDeleteAllHistory);
    
    // Notifications
    elements.notificationsBtn?.addEventListener('click', toggleNotificationsPanel);
    elements.clearNotificationsBtn?.addEventListener('click', clearNotifications);
    
    // Sound toggle
    elements.soundToggle?.addEventListener('click', toggleSound);
    
    // Modal close buttons
    document.querySelectorAll('.close-modal').forEach(button => {
        button.addEventListener('click', () => {
            elements.detailModal.classList.remove('active');
        });
    });
    
    // Confirm modal
    elements.confirmCancel?.addEventListener('click', () => {
        elements.confirmModal.classList.remove('active');
    });
    
    // Close modals on outside click
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.remove('active');
            }
        });
    });
    
    // Close notifications panel on outside click
    document.addEventListener('click', (e) => {
        if (!elements.notificationsPanel.contains(e.target) && 
            !elements.notificationsBtn.contains(e.target) &&
            elements.notificationsPanel.classList.contains('active')) {
            elements.notificationsPanel.classList.remove('active');
        }
    });
}

// Tab Navigation
function switchTab(tab) {
    // Update navigation
    elements.navItems.forEach(item => {
        item.classList.toggle('active', item.dataset.tab === tab);
    });
    
    // Update content sections
    elements.contentSections.forEach(section => {
        section.classList.toggle('active', section.id === `${tab}Section`);
    });
    
    // Update page title
    const titles = {
        dashboard: 'Dashboard',
        scan: 'New Scan',
        history: 'Scan History',
        patterns: 'Detection Patterns'
    };
    elements.pageTitle.textContent = titles[tab] || 'Dashboard';
    
    // Load data for the tab
    switch(tab) {
        case 'history':
            loadHistory();
            break;
        case 'patterns':
            loadDetectionPatterns();
            break;
        case 'dashboard':
            loadDashboardStats();
            loadRecentScans();
            break;
    }
}

// Results Tab Switching
function switchResultsTab(tab) {
    // Update tab buttons
    elements.tabButtons.forEach(button => {
        button.classList.toggle('active', button.dataset.tab === tab);
    });
    
    // Update tab contents
    elements.tabContents.forEach(content => {
        content.classList.toggle('active', content.id === `${tab}Tab`);
    });
}

// Connection Management
async function checkConnection() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/health`);
        if (response.ok) {
            elements.connectionStatus.innerHTML = '<i class="fas fa-circle"></i> <span>Connected</span>';
            elements.connectionStatus.classList.add('connected');
            showToast('Connected to server');
        }
    } catch (error) {
        elements.connectionStatus.innerHTML = '<i class="fas fa-circle"></i> <span>Disconnected</span>';
        elements.connectionStatus.classList.remove('connected');
        showToast('Server connection failed', 'error');
    }
}

// Dashboard Functions
async function loadDashboardStats() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/history?limit=100`);
        const data = await response.json();
        
        if (data.scans) {
            let totalSecrets = 0;
            let totalBuckets = 0;
            let totalVulnerable = 0;
            
            data.scans.forEach(scan => {
                if (scan.findings) {
                    const findings = typeof scan.findings === 'string' 
                        ? JSON.parse(scan.findings) 
                        : scan.findings;
                    
                    totalSecrets += findings.stats?.secrets_found || 0;
                    totalBuckets += findings.stats?.buckets_found || 0;
                    totalVulnerable += findings.stats?.vulnerable_buckets || 0;
                }
            });
            
            elements.totalScans.textContent = data.scans.length;
            elements.secretsFound.textContent = totalSecrets;
            elements.bucketsFound.textContent = totalBuckets;
            elements.vulnerableBuckets.textContent = totalVulnerable;
        }
    } catch (error) {
        console.error('Failed to load dashboard stats:', error);
    }
}

async function loadRecentScans() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/history?limit=10`);
        const data = await response.json();
        
        if (data.scans && data.scans.length > 0) {
            elements.recentScansTable.innerHTML = '';
            data.scans.forEach(scan => {
                const row = createHistoryRow(scan);
                elements.recentScansTable.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Failed to load recent scans:', error);
    }
}

// Scan Functions
async function handleScanSubmit(e) {
    e.preventDefault();
    
    const orgName = elements.orgName.value.trim();
    const scanType = elements.scanType.value;
    const includeBuckets = elements.includeBuckets.checked;
    
    if (!orgName) {
        showToast('Please enter a GitHub organization or username', 'error');
        return;
    }
    
    try {
        const params = new URLSearchParams({
            org_name: orgName,
            scan_type: scanType,
            include_buckets: includeBuckets
        });
        
        const response = await fetch(`${API_BASE_URL}/api/scan?${params}`, {
            method: 'POST'
        });
        
        if (response.ok) {
            const data = await response.json();
            currentScanId = data.scan_id;
            
            showToast('Scan started successfully');
            connectToWebSocket(currentScanId);
            
            // Show active scans card
            elements.activeScansCard.style.display = 'block';
            
            // Reset form
            resetScanForm();
        } else {
            const error = await response.json();
            showToast(error.detail || 'Failed to start scan', 'error');
        }
    } catch (error) {
        showToast('Failed to connect to server', 'error');
        console.error('Scan submission error:', error);
    }
}

function resetScanForm() {
    elements.scanForm.reset();
    elements.scanType.value = 'public';
    elements.includeBuckets.checked = true;
}

// WebSocket Connection
function connectToWebSocket(scanId) {
    if (activeWebSocket) {
        activeWebSocket.close();
    }
    
    const wsUrl = `ws://127.0.0.1:8000/ws/${scanId}`;
    activeWebSocket = new WebSocket(wsUrl);
    
    activeWebSocket.onopen = () => {
        console.log('WebSocket connected');
        // Send initial ping
        activeWebSocket.send('ping');
    };
    
    activeWebSocket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleWebSocketMessage(data);
        } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
        }
    };
    
    activeWebSocket.onclose = () => {
        console.log('WebSocket disconnected');
        activeWebSocket = null;
    };
    
    activeWebSocket.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
}

function handleWebSocketMessage(data) {
    switch(data.type) {
        case 'progress':
            updateScanProgress(data);
            break;
        case 'pong':
            // Keep connection alive
            break;
    }
}

function updateScanProgress(data) {
    const scanId = currentScanId;
    const phase = data.phase;
    const message = data.message;
    const progress = data.progress;
    
    // Add notification
    addNotification('Scan Update', message, phase);
    
    // Update active scans display
    let scanCard = document.getElementById(`scan-card-${scanId}`);
    
    if (!scanCard) {
        scanCard = createScanProgressCard(scanId);
        elements.activeScansContainer.appendChild(scanCard);
    }
    
    // Update card content
    const phaseElement = scanCard.querySelector(`.phase-progress[data-phase="${phase}"]`);
    if (phaseElement) {
        const progressBar = phaseElement.querySelector('.progress-fill');
        if (progressBar && progress !== undefined) {
            progressBar.style.width = `${progress}%`;
        }
        
        const progressText = phaseElement.querySelector('.progress-text');
        if (progressText) {
            progressText.textContent = `${Math.round(progress)}%`;
        }
    }
    
    // Update message
    const messageElement = scanCard.querySelector('.scan-message');
    if (messageElement) {
        messageElement.textContent = message;
    }
    
    // Update stats if provided
    if (data.data) {
        updateScanStats(scanId, data.data);
        
        // If phase 1 complete, show results
        if (data.data.phase === 'secret_scan_complete') {
            showScanResults(data.data);
        }
        
        // If phase 2 complete, update results
        if (data.data.phase === 'bucket_validation_complete') {
            updateBucketResults(data.data);
        }
    }
    
    // If scan completed, move to results
    if (phase === 'completed' || phase === 'failed' || phase === 'cancelled') {
        setTimeout(() => {
            scanCard.remove();
            if (elements.activeScansContainer.children.length === 0) {
                elements.activeScansCard.style.display = 'none';
            }
            
            // Load updated history
            loadDashboardStats();
            loadRecentScans();
        }, 3000);
    }
}

function createScanProgressCard(scanId) {
    const card = document.createElement('div');
    card.className = 'scan-progress-card';
    card.id = `scan-card-${scanId}`;
    
    card.innerHTML = `
        <div class="scan-progress-header">
            <div class="scan-progress-info">
                <h4>Scan ID: ${scanId}</h4>
                <p class="scan-message">Initializing...</p>
            </div>
            <button class="btn-icon cancel-scan" data-scan-id="${scanId}" title="Cancel Scan">
                <i class="fas fa-times"></i>
            </button>
        </div>
        
        <div class="phase-progress" data-phase="secret_scan">
            <span class="phase-label">Secret Scan</span>
            <div class="progress-container">
                <div class="progress-label">
                    <span>Progress</span>
                    <span class="progress-text">0%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: 0%"></div>
                </div>
            </div>
        </div>
        
        <div class="phase-progress" data-phase="bucket_validation" style="display: none;">
            <span class="phase-label">Bucket Validation</span>
            <div class="progress-container">
                <div class="progress-label">
                    <span>Progress</span>
                    <span class="progress-text">0%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: 0%"></div>
                </div>
            </div>
        </div>
        
        <div class="scan-stats">
            <div class="scan-stat">
                <div class="scan-stat-value" data-stat="repos_scanned">0</div>
                <div class="scan-stat-label">Repos Scanned</div>
            </div>
            <div class="scan-stat">
                <div class="scan-stat-value" data-stat="secrets_found">0</div>
                <div class="scan-stat-label">Secrets Found</div>
            </div>
            <div class="scan-stat">
                <div class="scan-stat-value" data-stat="bucket_urls">0</div>
                <div class="scan-stat-label">Bucket URLs</div>
            </div>
            <div class="scan-stat">
                <div class="scan-stat-value" data-stat="vulnerable_buckets">0</div>
                <div class="scan-stat-label">Vulnerable</div>
            </div>
        </div>
    `;
    
    // Add cancel button listener
    const cancelBtn = card.querySelector('.cancel-scan');
    cancelBtn.addEventListener('click', () => {
        cancelScan(scanId);
    });
    
    return card;
}

function updateScanStats(scanId, data) {
    const card = document.getElementById(`scan-card-${scanId}`);
    if (!card) return;
    
    // Show/hide bucket validation phase
    const bucketPhase = card.querySelector('.phase-progress[data-phase="bucket_validation"]');
    if (bucketPhase && data.phase === 'bucket_validation') {
        bucketPhase.style.display = 'flex';
    }
    
    // Update stats
    if (data.stats) {
        const stats = data.stats;
        card.querySelector('[data-stat="repos_scanned"]').textContent = stats.scanned_repos || 0;
        card.querySelector('[data-stat="secrets_found"]').textContent = stats.secrets_found || 0;
        card.querySelector('[data-stat="bucket_urls"]').textContent = stats.bucket_urls_found || 0;
        card.querySelector('[data-stat="vulnerable_buckets"]').textContent = stats.vulnerable_buckets || 0;
    }
}

// Results Display
function showScanResults(data) {
    elements.scanResultsCard.style.display = 'block';
    
    // Store current results
    currentResults = data;
    
    // Update summary
    updateScanSummary(data);
    
    // Update secrets table
    updateSecretsTable(data.secrets || []);
    
    // Update bucket URLs table (phase 1 results)
    updateBucketUrlsTable(data.bucket_urls || []);
    
    // Switch to results tab
    switchTab('scan');
    
    // Scroll to results
    elements.scanResultsCard.scrollIntoView({ behavior: 'smooth' });
}

function updateScanSummary(data) {
    const stats = data.stats || {};
    
    elements.scanSummary.innerHTML = `
        <div class="summary-item">
            <div class="summary-value">${stats.total_repos || 0}</div>
            <div class="summary-label">Total Repositories</div>
        </div>
        <div class="summary-item">
            <div class="summary-value secrets">${stats.secrets_found || 0}</div>
            <div class="summary-label">Secrets Found</div>
        </div>
        <div class="summary-item">
            <div class="summary-value buckets">${stats.bucket_urls_found || 0}</div>
            <div class="summary-label">Bucket URLs Found</div>
        </div>
        <div class="summary-item">
            <div class="summary-value vulnerable">${stats.vulnerable_buckets || 0}</div>
            <div class="summary-label">Vulnerable Buckets</div>
        </div>
    `;
}

function updateSecretsTable(secrets) {
    const tbody = elements.secretsTable.querySelector('tbody');
    tbody.innerHTML = '';
    
    if (secrets.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="7" class="empty-state">
                    <i class="fas fa-key"></i>
                    <p>No secrets found</p>
                </td>
            </tr>
        `;
        return;
    }
    
    secrets.forEach(secret => {
        const row = document.createElement('tr');
        
        // Severity class
        const severityClass = `severity-${secret.severity || 'medium'}`;
        
        row.innerHTML = `
            <td><span class="monospace">${secret.type}</span></td>
            <td><span class="severity-badge ${severityClass}">${secret.severity || 'medium'}</span></td>
            <td>${secret.repo || 'N/A'}</td>
            <td><span class="text-truncate" title="${secret.file || ''}">${secret.file || 'N/A'}</span></td>
            <td>${secret.line || 'N/A'}</td>
            <td><span class="monospace">${secret.value || ''}</span></td>
            <td>
                <div class="action-buttons">
                    <button class="action-btn view-details" title="View Details">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="action-btn copy-secret" title="Copy to Clipboard">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
            </td>
        `;
        
        // Add event listeners
        const viewBtn = row.querySelector('.view-details');
        viewBtn.addEventListener('click', () => showSecretDetails(secret));
        
        const copyBtn = row.querySelector('.copy-secret');
        copyBtn.addEventListener('click', () => copyToClipboard(secret.value));
        
        tbody.appendChild(row);
    });
}

function updateBucketUrlsTable(bucketUrls) {
    const tbody = elements.bucketsTable.querySelector('tbody');
    tbody.innerHTML = '';
    
    if (bucketUrls.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="6" class="empty-state">
                    <i class="fas fa-cloud"></i>
                    <p>No bucket URLs found</p>
                </td>
            </tr>
        `;
        return;
    }
    
    bucketUrls.forEach(bucket => {
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td><span class="bucket-status pending">⏳ Pending</span></td>
            <td><span class="monospace text-truncate" title="${bucket.url}">${bucket.url}</span></td>
            <td>${bucket.type}</td>
            <td>-</td>
            <td>-</td>
            <td>
                <div class="action-buttons">
                    <button class="action-btn copy-url" title="Copy URL">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
            </td>
        `;
        
        // Add event listener
        const copyBtn = row.querySelector('.copy-url');
        copyBtn.addEventListener('click', () => copyToClipboard(bucket.url));
        
        tbody.appendChild(row);
    });
}

function updateBucketResults(data) {
    const buckets = data.buckets || [];
    const tbody = elements.bucketsTable.querySelector('tbody');
    
    // Clear existing rows except headers
    const existingRows = tbody.querySelectorAll('tr');
    existingRows.forEach(row => row.remove());
    
    if (buckets.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="6" class="empty-state">
                    <i class="fas fa-cloud"></i>
                    <p>No bucket scan results</p>
                </td>
            </tr>
        `;
        return;
    }
    
    buckets.forEach(bucket => {
        const row = document.createElement('tr');
        
        // Determine status class
        let statusClass = 'unknown';
        let statusText = bucket.status || 'Unknown';
        
        if (bucket.vulnerable) {
            statusClass = 'vulnerable';
            statusText = '🚨 Vulnerable';
        } else if (bucket.status?.includes('Protected')) {
            statusClass = 'protected';
            statusText = '🔒 Protected';
        } else if (bucket.status?.includes('Public')) {
            statusClass = 'public';
            statusText = '🌐 Public';
        }
        
        row.innerHTML = `
            <td><span class="bucket-status ${statusClass}">${statusText}</span></td>
            <td><span class="monospace text-truncate" title="${bucket.url}">${bucket.url}</span></td>
            <td>${bucket.type}</td>
            <td>${bucket.response_code || '-'}</td>
            <td>${bucket.response_time ? `${bucket.response_time}s` : '-'}</td>
            <td>
                <div class="action-buttons">
                    <button class="action-btn copy-url" title="Copy URL">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
            </td>
        `;
        
        // Add event listener
        const copyBtn = row.querySelector('.copy-url');
        copyBtn.addEventListener('click', () => copyToClipboard(bucket.url));
        
        tbody.appendChild(row);
    });
}

// Filter Functions
function filterSecretsBySeverity(severity) {
    const rows = elements.secretsTable.querySelectorAll('tbody tr');
    
    rows.forEach(row => {
        if (row.classList.contains('empty-row')) return;
        
        const severityCell = row.querySelector('.severity-badge');
        if (severityCell) {
            const rowSeverity = severityCell.textContent.toLowerCase();
            const show = severity === 'all' || rowSeverity === severity;
            row.style.display = show ? '' : 'none';
        }
    });
}

// History Functions
async function loadHistory() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/history?limit=50`);
        const data = await response.json();
        
        if (data.scans && data.scans.length > 0) {
            elements.historyTable.querySelector('tbody').innerHTML = '';
            data.scans.forEach(scan => {
                const row = createHistoryRow(scan);
                elements.historyTable.querySelector('tbody').appendChild(row);
            });
        } else {
            elements.historyTable.querySelector('tbody').innerHTML = `
                <tr>
                    <td colspan="8" class="empty-state">
                        <i class="fas fa-search"></i>
                        <p>No scan history found</p>
                    </td>
                </tr>
            `;
        }
    } catch (error) {
        console.error('Failed to load history:', error);
        showToast('Failed to load scan history', 'error');
    }
}

function createHistoryRow(scan) {
    const row = document.createElement('tr');
    
    // Parse findings
    let findings = {};
    if (scan.findings) {
        findings = typeof scan.findings === 'string' 
            ? JSON.parse(scan.findings) 
            : scan.findings;
    }
    
    const stats = findings.stats || {};
    
    // Format date
    const date = new Date(scan.created_at);
    const formattedDate = date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
    
    // Status badge
    let statusBadge = '';
    if (scan.status === 'completed') {
        statusBadge = '<span class="status-badge completed">Completed</span>';
    } else if (scan.status === 'running') {
        statusBadge = '<span class="status-badge running">Running</span>';
    } else if (scan.status === 'failed') {
        statusBadge = '<span class="status-badge failed">Failed</span>';
    } else if (scan.status === 'cancelled') {
        statusBadge = '<span class="status-badge cancelled">Cancelled</span>';
    }
    
    row.innerHTML = `
        <td>${scan.id}</td>
        <td>${scan.org_name}</td>
        <td>${scan.scan_type}</td>
        <td>${statusBadge}</td>
        <td>${stats.secrets_found || 0}</td>
        <td>${stats.buckets_found || 0}</td>
        <td>${formattedDate}</td>
        <td>
            <div class="action-buttons">
                <button class="action-btn view-scan" title="View Scan" data-scan-id="${scan.id}">
                    <i class="fas fa-eye"></i>
                </button>
                <button class="action-btn delete-scan" title="Delete Scan" data-scan-id="${scan.id}">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </td>
    `;
    
    // Add event listeners
    const viewBtn = row.querySelector('.view-scan');
    viewBtn.addEventListener('click', () => viewScanDetails(scan.id));
    
    const deleteBtn = row.querySelector('.delete-scan');
    deleteBtn.addEventListener('click', () => confirmDeleteScan(scan.id));
    
    return row;
}

function filterHistory() {
    const searchTerm = elements.historySearch.value.toLowerCase();
    const statusFilter = elements.historyStatusFilter.value;
    
    const rows = elements.historyTable.querySelectorAll('tbody tr');
    
    rows.forEach(row => {
        if (row.classList.contains('empty-state')) return;
        
        const orgName = row.cells[1].textContent.toLowerCase();
        const status = row.cells[3].querySelector('.status-badge')?.textContent.toLowerCase() || '';
        
        const matchesSearch = orgName.includes(searchTerm);
        const matchesStatus = statusFilter === 'all' || status.includes(statusFilter);
        
        row.style.display = matchesSearch && matchesStatus ? '' : 'none';
    });
}

// Patterns Functions
async function loadDetectionPatterns() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/patterns`);
        const data = await response.json();
        
        // Secret patterns
        elements.secretPatternsGrid.innerHTML = '';
        if (data.secret_patterns) {
            data.secret_patterns.forEach(pattern => {
                const card = document.createElement('div');
                card.className = 'pattern-card';
                card.innerHTML = `
                    <h5>${pattern.name}</h5>
                    <p>${pattern.description}</p>
                `;
                elements.secretPatternsGrid.appendChild(card);
            });
        }
        
        // Bucket patterns
        elements.bucketPatternsGrid.innerHTML = '';
        if (data.bucket_patterns) {
            data.bucket_patterns.forEach(pattern => {
                const card = document.createElement('div');
                card.className = 'pattern-card';
                card.innerHTML = `
                    <h5>${pattern}</h5>
                    <p>Cloud storage bucket URL pattern</p>
                `;
                elements.bucketPatternsGrid.appendChild(card);
            });
        }
    } catch (error) {
        console.error('Failed to load patterns:', error);
    }
}

// Scan Management
async function cancelScan(scanId) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/scan/${scanId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showToast('Scan cancelled successfully');
            
            // Remove scan card
            const card = document.getElementById(`scan-card-${scanId}`);
            if (card) {
                card.remove();
            }
            
            if (elements.activeScansContainer.children.length === 0) {
                elements.activeScansCard.style.display = 'none';
            }
            
            // Update history
            loadDashboardStats();
            loadRecentScans();
        } else {
            const error = await response.json();
            showToast(error.detail || 'Failed to cancel scan', 'error');
        }
    } catch (error) {
        showToast('Failed to cancel scan', 'error');
        console.error('Cancel scan error:', error);
    }
}

async function viewScanDetails(scanId) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/scan/${scanId}`);
        const scan = await response.json();
        
        // Parse findings
        let findings = {};
        if (scan.findings) {
            findings = typeof scan.findings === 'string' 
                ? JSON.parse(scan.findings) 
                : scan.findings;
        }
        
        // Show in modal
        elements.modalTitle.textContent = `Scan Details - ID: ${scanId}`;
        
        let modalContent = `
            <div class="scan-details">
                <div class="detail-group">
                    <h4>Scan Information</h4>
                    <p><strong>Organization/User:</strong> ${scan.org_name}</p>
                    <p><strong>Scan Type:</strong> ${scan.scan_type}</p>
                    <p><strong>Status:</strong> ${scan.status}</p>
                    <p><strong>Started:</strong> ${new Date(scan.created_at).toLocaleString()}</p>
                    ${scan.updated_at ? `<p><strong>Updated:</strong> ${new Date(scan.updated_at).toLocaleString()}</p>` : ''}
                </div>
        `;
        
        if (findings.stats) {
            modalContent += `
                <div class="detail-group">
                    <h4>Results Summary</h4>
                    <p><strong>Repositories Scanned:</strong> ${findings.stats.scanned_repos || 0} / ${findings.stats.total_repos || 0}</p>
                    <p><strong>Secrets Found:</strong> ${findings.stats.secrets_found || 0}</p>
                    <p><strong>Bucket URLs Found:</strong> ${findings.stats.bucket_urls_found || 0}</p>
                    <p><strong>Vulnerable Buckets:</strong> ${findings.stats.vulnerable_buckets || 0}</p>
                </div>
            `;
        }
        
        if (findings.secrets && findings.secrets.length > 0) {
            modalContent += `
                <div class="detail-group">
                    <h4>Top Secrets Found</h4>
                    <ul>
            `;
            
            findings.secrets.slice(0, 5).forEach(secret => {
                modalContent += `<li><strong>${secret.type}</strong> in ${secret.repo}/${secret.file}:${secret.line}</li>`;
            });
            
            if (findings.secrets.length > 5) {
                modalContent += `<li>... and ${findings.secrets.length - 5} more</li>`;
            }
            
            modalContent += `
                    </ul>
                </div>
            `;
        }
        
        modalContent += `</div>`;
        
        elements.modalBody.innerHTML = modalContent;
        elements.detailModal.classList.add('active');
        
    } catch (error) {
        console.error('Failed to load scan details:', error);
        showToast('Failed to load scan details', 'error');
    }
}

// Delete Functions
function confirmDeleteScan(scanId) {
    elements.confirmMessage.textContent = `Are you sure you want to delete scan #${scanId}? This action cannot be undone.`;
    elements.confirmModal.classList.add('active');
    
    elements.confirmOk.onclick = () => {
        deleteScan(scanId);
        elements.confirmModal.classList.remove('active');
    };
}

function confirmDeleteAllHistory() {
    elements.confirmMessage.textContent = 'Are you sure you want to delete ALL scan history? This action cannot be undone.';
    elements.confirmModal.classList.add('active');
    
    elements.confirmOk.onclick = () => {
        deleteAllHistory();
        elements.confirmModal.classList.remove('active');
    };
}

async function deleteScan(scanId) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/history?scan_id=${scanId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showToast('Scan deleted successfully');
            loadHistory();
            loadDashboardStats();
            loadRecentScans();
        } else {
            const error = await response.json();
            showToast(error.detail || 'Failed to delete scan', 'error');
        }
    } catch (error) {
        showToast('Failed to delete scan', 'error');
        console.error('Delete scan error:', error);
    }
}

async function deleteAllHistory() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/history?delete_all=true`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showToast('All scan history deleted successfully');
            loadHistory();
            loadDashboardStats();
            loadRecentScans();
        } else {
            const error = await response.json();
            showToast(error.detail || 'Failed to delete history', 'error');
        }
    } catch (error) {
        showToast('Failed to delete history', 'error');
        console.error('Delete all history error:', error);
    }
}

// Detail Views
function showSecretDetails(secret) {
    elements.modalTitle.textContent = `Secret Details - ${secret.type}`;
    
    const details = `
        <div class="secret-details">
            <div class="detail-group">
                <h4>Secret Information</h4>
                <p><strong>Type:</strong> ${secret.type}</p>
                <p><strong>Severity:</strong> <span class="severity-badge severity-${secret.severity || 'medium'}">${secret.severity || 'medium'}</span></p>
                <p><strong>Repository:</strong> ${secret.repo || 'N/A'}</p>
                <p><strong>File:</strong> ${secret.file_path || secret.file || 'N/A'}</p>
                <p><strong>Line:</strong> ${secret.line || 'N/A'}</p>
                <p><strong>Found:</strong> ${secret.timestamp ? new Date(secret.timestamp).toLocaleString() : 'N/A'}</p>
            </div>
            
            <div class="detail-group">
                <h4>Secret Value</h4>
                <div class="code-block">
                    <pre><code>${secret.full_value || secret.value || 'N/A'}</code></pre>
                </div>
                <button class="btn-secondary copy-full-secret" style="margin-top: 12px;">
                    <i class="fas fa-copy"></i> Copy Full Value
                </button>
            </div>
            
            ${secret.context ? `
            <div class="detail-group">
                <h4>Context</h4>
                <div class="code-block">
                    <pre><code>${secret.context}</code></pre>
                </div>
            </div>
            ` : ''}
        </div>
    `;
    
    elements.modalBody.innerHTML = details;
    elements.detailModal.classList.add('active');
    
    // Add copy button listener
    const copyBtn = elements.modalBody.querySelector('.copy-full-secret');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            copyToClipboard(secret.full_value || secret.value);
            showToast('Secret copied to clipboard');
        });
    }
}

// Notification Functions
function addNotification(title, message, type = 'info') {
    const notification = {
        id: Date.now(),
        title,
        message,
        type,
        timestamp: new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})
    };
    
    notifications.unshift(notification);
    updateNotificationsDisplay();
    
    // Play sound if enabled
    if (soundEnabled) {
        playBeepSound();
    }
}

function updateNotificationsDisplay() {
    // Update badge
    elements.notificationBadge.textContent = notifications.length;
    elements.notificationBadge.style.display = notifications.length > 0 ? 'flex' : 'none';
    
    // Update list
    elements.notificationsList.innerHTML = '';
    
    if (notifications.length === 0) {
        elements.notificationsList.innerHTML = `
            <div class="notification-empty">
                <i class="fas fa-bell-slash"></i>
                <p>No notifications</p>
            </div>
        `;
        return;
    }
    
    notifications.forEach(notification => {
        const notificationElement = document.createElement('div');
        notificationElement.className = 'notification-item';
        
        // Determine icon based on type
        let icon = 'fas fa-info-circle';
        if (notification.type.includes('error') || notification.type.includes('failed')) {
            icon = 'fas fa-exclamation-circle';
        } else if (notification.type.includes('success') || notification.type.includes('completed')) {
            icon = 'fas fa-check-circle';
        } else if (notification.type.includes('warning')) {
            icon = 'fas fa-exclamation-triangle';
        }
        
        notificationElement.innerHTML = `
            <div class="notification-header">
                <div class="notification-title">
                    <i class="${icon}"></i>
                    ${notification.title}
                </div>
                <div class="notification-time">${notification.timestamp}</div>
            </div>
            <div class="notification-message">${notification.message}</div>
        `;
        
        elements.notificationsList.appendChild(notificationElement);
    });
}

function toggleNotificationsPanel() {
    elements.notificationsPanel.classList.toggle('active');
}

function clearNotifications() {
    notifications = [];
    updateNotificationsDisplay();
    showToast('Notifications cleared');
}

// Sound Functions
function toggleSound() {
    soundEnabled = !soundEnabled;
    const icon = elements.soundToggle.querySelector('i');
    
    if (soundEnabled) {
        icon.className = 'fas fa-volume-up';
        showToast('Sound enabled');
    } else {
        icon.className = 'fas fa-volume-mute';
        showToast('Sound disabled');
    }
}

function playBeepSound() {
    if (soundEnabled && elements.beepSound) {
        elements.beepSound.currentTime = 0;
        elements.beepSound.play().catch(e => console.log('Audio play failed:', e));
    }
}

// Utility Functions
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard');
    }).catch(err => {
        console.error('Failed to copy:', err);
        showToast('Failed to copy', 'error');
    });
}

function copyResultsToClipboard() {
    const results = JSON.stringify(currentResults, null, 2);
    copyToClipboard(results);
}

function showToast(message, type = 'success') {
    elements.toastMessage.textContent = message;
    
    // Update icon based on type
    const icon = elements.toast.querySelector('i');
    if (type === 'error') {
        icon.className = 'fas fa-exclamation-circle';
        icon.style.color = 'var(--danger)';
    } else if (type === 'warning') {
        icon.className = 'fas fa-exclamation-triangle';
        icon.style.color = 'var(--warning)';
    } else {
        icon.className = 'fas fa-check-circle';
        icon.style.color = 'var(--success)';
    }
    
    elements.toast.classList.add('active');
    
    setTimeout(() => {
        elements.toast.classList.remove('active');
    }, 3000);
}

// Add some CSS for the modal content
const style = document.createElement('style');
style.textContent = `
    .detail-group {
        margin-bottom: 24px;
    }
    
    .detail-group h4 {
        font-size: 16px;
        margin-bottom: 12px;
        color: var(--text-primary);
        border-bottom: 1px solid var(--border-light);
        padding-bottom: 8px;
    }
    
    .detail-group p {
        margin-bottom: 8px;
        color: var(--text-secondary);
    }
    
    .detail-group strong {
        color: var(--text-primary);
        min-width: 120px;
        display: inline-block;
    }
    
    .code-block {
        background: var(--bg-primary);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        padding: 16px;
        overflow-x: auto;
        font-family: 'JetBrains Mono', monospace;
        font-size: 13px;
        color: var(--text-primary);
    }
    
    .code-block pre {
        margin: 0;
        white-space: pre-wrap;
        word-wrap: break-word;
    }
    
    .secret-details .severity-badge {
        display: inline-block;
        margin-left: 8px;
        vertical-align: middle;
    }
`;
document.head.appendChild(style);