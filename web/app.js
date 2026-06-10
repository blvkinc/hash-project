/* =======================================
   IntegrityGuard - Frontend Application
   Timeline view, baseline tracking,
   per-file change history with automated analysis
   ======================================= */

const API = window.location.origin + '/api';
let currentFilter = 'all';
let allFiles = [];
let selectedFilePath = null;
let selectedFileId = null;
let searchQuery = '';
let watchedRoots = [];
let collapsedTreeNodes = new Set();
let expandedTreeDirs = new Set();
let systemMonitorEnabled = false;
let knownAlertIds = new Set();
let alertsInitialized = false;
let desktopNotificationRequested = false;
let toastAlertsEnabled = true;
let desktopAlertsEnabled = false;
let notificationHistory = [];
let notificationCenterOpen = false;
let readNotificationIds = new Set();

/* --- DOM Refs -------------------------------- */
const $ = id => document.getElementById(id);

const el = {
    statFiles: $('statFiles'),
    statPending: $('statPending'),
    statCritical: $('statCritical'),
    statHigh: $('statHigh'),
    statMedium: $('statMedium'),
    statLow: $('statLow'),
    statInfo: $('statInfo'),
    scanPath: $('scanPath'),
    scanStatus: $('scanStatus'),
    scanProgress: $('scanProgress'),
    scanProgressLabel: $('scanProgressLabel'),
    scanProgressCount: $('scanProgressCount'),
    scanProgressBar: $('scanProgressBar'),
    scanProgressMetrics: $('scanProgressMetrics'),
    navAnalysisCount: $('navAnalysisCount'),
    hashAlgorithm: $('hashAlgorithm'),
    reanalyzeExisting: $('reanalyzeExisting'),
    watcherStatus: $('watcherStatus'),
    systemMonitorBtn: $('systemMonitorBtn'),
    systemMonitorLabel: $('systemMonitorLabel'),
    toastContainer: $('toastContainer'),
    navTime: $('navTime'),
    filterGroup: $('filterGroup'),
    filterCounts: {
        all: $('filterAllCount'),
        critical: $('filterCriticalCount'),
        high: $('filterHighCount'),
        medium: $('filterMediumCount'),
        low: $('filterLowCount'),
        info: $('filterInfoCount'),
    },
    toastAlerts: $('toastAlerts'),
    desktopAlerts: $('desktopAlerts'),
    notificationCenterBtn: $('notificationCenterBtn'),
    notificationUnreadCount: $('notificationUnreadCount'),
    notificationCenter: $('notificationCenter'),
    notificationCenterSubtitle: $('notificationCenterSubtitle'),
    notificationList: $('notificationList'),
    fileSidebar: $('fileSidebar'),
    fileList: $('fileList'),
    fileSearch: $('fileSearch'),
    sidebarCount: $('sidebarCount'),
    timelinePanel: $('timelinePanel'),
    timelineEmpty: $('timelineEmpty'),
    timelineContent: $('timelineContent'),
    timelineHeader: $('timelineHeader'),
    timelineTrack: $('timelineTrack'),
};

/* --- Boot ------------------------------------ */
document.addEventListener('DOMContentLoaded', () => {
    initNotificationCenter();
    initNotificationPolicy();
    tick();
    refresh();
    setInterval(refresh, 3000);
    setInterval(tick, 1000);
});

function initNotificationPolicy() {
    toastAlertsEnabled = localStorage.getItem('ig_toast_alerts') !== '0';
    desktopAlertsEnabled = localStorage.getItem('ig_desktop_alerts') === '1';

    if (el.toastAlerts) {
        el.toastAlerts.checked = toastAlertsEnabled;
        el.toastAlerts.addEventListener('change', () => {
            toastAlertsEnabled = !!el.toastAlerts.checked;
            localStorage.setItem('ig_toast_alerts', toastAlertsEnabled ? '1' : '0');
        });
    }

    if (el.desktopAlerts) {
        el.desktopAlerts.checked = desktopAlertsEnabled;
        el.desktopAlerts.addEventListener('change', async () => {
            desktopAlertsEnabled = !!el.desktopAlerts.checked;
            localStorage.setItem('ig_desktop_alerts', desktopAlertsEnabled ? '1' : '0');
            if (desktopAlertsEnabled && 'Notification' in window && Notification.permission === 'default') {
                desktopNotificationRequested = true;
                const permission = await Notification.requestPermission();
                if (permission !== 'granted') {
                    desktopAlertsEnabled = false;
                    el.desktopAlerts.checked = false;
                    localStorage.setItem('ig_desktop_alerts', '0');
                }
            }
        });
    }
}

function tick() {
    const now = new Date();
    el.navTime.textContent = now.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function refresh() {
    fetchStats();
    fetchBaseline();
    fetchWatcherStatus();
    fetchSystemMonitorStatus();
    fetchScanStatus();
    fetchPriorityAlerts();
    fetchNotificationHistory();
    if (selectedFilePath || selectedFileId) fetchFileTimeline(selectedFilePath, selectedFileId);
}

function initNotificationCenter() {
    try {
        readNotificationIds = new Set(JSON.parse(localStorage.getItem('ig_read_notifications') || '[]'));
    } catch {
        readNotificationIds = new Set();
    }
}

async function fetchScanStatus() {
    try {
        const r = await fetch(`${API}/scan/status`);
        const d = await parseApiPayload(r);
        if (!r.ok) return;
        renderScanProgress(d);
    } catch (e) {
        console.error('Scan status error', e);
    }
}

function renderScanProgress(scan) {
    if (!el.scanProgress) return;

    const active = !!scan.active;
    const hasResult = !!scan.completed_at || scan.stage === 'complete' || scan.stage === 'error';
    el.scanProgress.hidden = !(active || hasResult);
    if (el.scanProgress.hidden) return;

    const total = Math.max(0, Number(scan.total) || 0);
    const processed = Math.max(0, Number(scan.processed) || 0);
    const percent = total ? Math.min(100, Math.round((processed / total) * 100)) : Number(scan.percent || 0);
    const message = scan.message || (active ? 'Scan running' : 'Scan idle');

    el.scanProgress.classList.toggle('is-active', active);
    el.scanProgress.classList.toggle('is-error', scan.stage === 'error');
    el.scanProgressLabel.textContent = message;
    el.scanProgressCount.textContent = total ? `${processed} / ${total}` : (scan.stage || 'idle');
    el.scanProgressBar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
    renderScanMetrics(scan);
}

function renderScanMetrics(scan) {
    if (!el.scanProgressMetrics) return;
    const filesPerSecond = Number(scan.files_per_second || 0);
    const mbPerSecond = Number(scan.mb_per_second || 0);
    const bytesProcessed = Number(scan.bytes_processed || 0);
    const elapsed = Number(scan.elapsed_seconds || 0);
    const hashSeconds = Number(scan.hash_seconds || 0);
    const dbSeconds = Number(scan.db_commit_seconds || 0);
    const commits = Number(scan.commit_count || 0);
    const errors = Number(scan.errors || 0);
    const hashWorkers = Number(scan.hash_workers || 0);

    const metrics = [];
    if (filesPerSecond || mbPerSecond || bytesProcessed) {
        metrics.push(['Files/s', filesPerSecond.toFixed(1)]);
        metrics.push(['Hash rate', `${mbPerSecond.toFixed(1)} MB/s`]);
        metrics.push(['Hashed', fmtSize(bytesProcessed)]);
    }
    if (elapsed) metrics.push(['Elapsed', fmtDuration(elapsed)]);
    if (hashSeconds) metrics.push(['Hash time', fmtDuration(hashSeconds)]);
    if (hashWorkers > 1) metrics.push(['Workers', String(hashWorkers)]);
    if (dbSeconds || commits) metrics.push(['DB commits', `${commits} / ${fmtDuration(dbSeconds)}`]);
    if (errors) metrics.push(['Errors', String(errors)]);

    el.scanProgressMetrics.innerHTML = metrics
        .map(([label, value]) => `<span>${esc(label)} <strong>${esc(value)}</strong></span>`)
        .join('');
}

/* --- Stats ----------------------------------- */
async function fetchStats() {
    try {
        const r = await fetch(`${API}/stats`);
        const d = await parseApiPayload(r);
        if (!r.ok) {
            console.error('Stats API error', d.detail || r.status);
            return;
        }
        bump(el.statFiles, d.monitored_files);
        bump(el.statCritical, d.critical);
        bump(el.statHigh, d.high);
        bump(el.statMedium, d.medium);
        bump(el.statLow, d.low);
        bump(el.statInfo, d.info);
        if (el.statPending) bump(el.statPending, d.pending_analysis ?? d.pending ?? 0);
        if (el.hashAlgorithm) {
            const mode = String(d.hash_mode || '').toLowerCase();
            const algorithm = String(d.hash_algorithm || 'unknown').toUpperCase();
            const security = String(d.security_hash_algorithm || '').toUpperCase();
            const threads = d.blake3_max_threads
                ? ` ${String(d.blake3_max_threads).toUpperCase()}`
                : '';
            el.hashAlgorithm.textContent = mode === 'hybrid' && security
                ? `Hybrid ${algorithm} + ${security}`
                : `Hash ${algorithm}${threads}`;
        }
        setQueueMeter(d.pending_analysis ?? d.pending ?? 0);
    } catch (e) {
        console.error('Stats error', e);
    }
}

function setQueueMeter(count) {
    if (!el.navAnalysisCount) return;
    const safeCount = Math.max(0, Number(count) || 0);
    el.navAnalysisCount.textContent = safeCount > 99
        ? '99+'
        : String(safeCount).padStart(2, '0');
}

function bump(node, val) {
    if (parseInt(node.textContent, 10) === val) return;
    node.textContent = val;
    node.style.transform = 'scale(1.12)';
    setTimeout(() => {
        node.style.transform = 'scale(1)';
    }, 180);
}

/* --- Watcher Status -------------------------- */
async function fetchWatcherStatus() {
    try {
        const r = await fetch(`${API}/watch/status`);
        const d = await parseApiPayload(r);
        const pill = el.watcherStatus;
        const label = pill.querySelector('.watcher-label');

        if (!r.ok) {
            pill.classList.remove('active');
            label.textContent = 'Offline (API error)';
            return;
        }

        watchedRoots = Array.isArray(d.paths) ? d.paths : (d.path ? [d.path] : []);

        const validRoots = new Set(watchedRoots);
        for (const node of Array.from(collapsedTreeNodes)) {
            if (!validRoots.has(node)) collapsedTreeNodes.delete(node);
        }

        if (d.active) {
            pill.classList.add('active');
            if (watchedRoots.length > 1) {
                label.textContent = `Watching ${watchedRoots.length} paths`;
            } else {
                label.textContent = `Watching ${shortenPath(watchedRoots[0] || '')}`;
            }
        } else {
            pill.classList.remove('active');
            label.textContent = 'Offline';
            watchedRoots = [];
        }

        renderFileList();
    } catch (e) {
        const pill = el.watcherStatus;
        const label = pill.querySelector('.watcher-label');
        pill.classList.remove('active');
        label.textContent = 'Offline (API unreachable)';
        console.error('Watch status error', e);
    }
}

async function fetchSystemMonitorStatus() {
    try {
        const r = await fetch(`${API}/system-monitor/status`);
        const d = await parseApiPayload(r);
        if (!r.ok) {
            console.error('System monitor status API error', d.detail || r.status);
            return;
        }
        systemMonitorEnabled = !!d.enabled;

        if (el.systemMonitorLabel) {
            const fsCount = Number(d.count || 0);
            const regCount = Number(d.registry_count || 0);
            el.systemMonitorLabel.textContent = systemMonitorEnabled
                ? `System Monitor: On (${fsCount} FS${regCount ? `, ${regCount} Reg` : ''})`
                : 'System Monitor: Off';
        }

        if (el.systemMonitorBtn) {
            el.systemMonitorBtn.classList.toggle('active', systemMonitorEnabled);
        }
    } catch (e) {
        console.error('System monitor status error', e);
    }
}

async function toggleSystemMonitor() {
    try {
        const targetState = !systemMonitorEnabled;
        const r = await fetch(`${API}/system-monitor/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: targetState })
        });
        const d = await parseApiPayload(r);

        if (r.ok) {
            systemMonitorEnabled = !!d.enabled;
            feedback(d.message || 'System monitor updated.', 'ok');
            toast(
                d.message || 'System monitor updated',
                systemMonitorEnabled ? 'toast-high' : 'toast-success'
            );
            fetchSystemMonitorStatus();
            fetchWatcherStatus();
            fetchScanStatus();
            fetchBaseline();
        } else {
            feedback(d.detail || 'Failed to toggle system monitor', 'error');
        }
    } catch (e) {
        feedback(e.message, 'error');
    }
}

async function stopWatcherForPath(path) {
    try {
        const r = await fetch(`${API}/watch/stop?path=${encodeURIComponent(path)}`, {
            method: 'POST'
        });
        const d = await parseApiPayload(r);
        if (r.ok) {
            feedback(d.message || `Watcher stopped for ${shortenPath(path)}`, 'info');
            toast(d.message || `Stopped ${shortenPath(path)}`, 'toast-success');
            fetchWatcherStatus();
            fetchSystemMonitorStatus();
        } else {
            feedback(d.detail || 'Failed to stop watcher', 'error');
        }
    } catch (e) {
        feedback(e.message, 'error');
    }
}

/* --- Alerts ---------------------------------- */
async function fetchPriorityAlerts() {
    try {
        const r = await fetch(`${API}/logs?limit=40`);
        const logs = await r.json();
        if (!Array.isArray(logs)) return;

        if (!alertsInitialized) {
            knownAlertIds = new Set(logs.map(l => l.id));
            alertsInitialized = true;
            return;
        }

        const fresh = logs.filter(l => !knownAlertIds.has(l.id));
        fresh.forEach(l => knownAlertIds.add(l.id));

        for (const log of fresh) {
            if (log.priority !== 'critical' && log.priority !== 'high') continue;
            const cls = log.priority === 'critical' ? 'toast-critical' : 'toast-high';
            const msg = `${log.priority.toUpperCase()}: ${fileName(log.path)} (${log.event_type})`;
            if (toastAlertsEnabled) toast(msg, cls);
            if (desktopAlertsEnabled) notifyDesktop(log);
        }

        if (knownAlertIds.size > 1200) {
            knownAlertIds = new Set(logs.map(l => l.id));
        }
    } catch (e) {
        console.error('Priority alert error', e);
    }
}

async function notifyDesktop(log) {
    if (!('Notification' in window)) return;
    if (!desktopAlertsEnabled) return;

    if (Notification.permission === 'granted') {
        showDesktopNotification(log);
        return;
    }

    if (Notification.permission !== 'default' || desktopNotificationRequested) {
        return;
    }

    desktopNotificationRequested = true;
    try {
        const permission = await Notification.requestPermission();
        if (permission === 'granted') {
            showDesktopNotification(log);
        }
    } catch (e) {
        console.error('Desktop notification permission error', e);
    }
}

function showDesktopNotification(log) {
    const priority = (log.priority || '').toUpperCase();
    const title = `IntegrityGuard ${priority} Alert`;
    const body = `${fileName(log.path)} (${log.event_type})`;
    const notification = new Notification(title, {
        body,
        tag: `integrityguard-${log.id}`,
        requireInteraction: log.priority === 'critical'
    });
    notification.onclick = () => window.focus();
}

async function fetchNotificationHistory() {
    try {
        const r = await fetch(`${API}/notifications/history?limit=80`);
        const history = await parseApiPayload(r);
        if (!r.ok || !Array.isArray(history)) return;
        notificationHistory = history.slice().reverse();
        renderNotificationCenter();
    } catch (e) {
        console.error('Notification history error', e);
    }
}

function notificationKey(item) {
    return String(item.event_id || `${item.timestamp}|${item.path}|${item.dispatch_type}`);
}

function unreadNotifications() {
    return notificationHistory.filter(item => !readNotificationIds.has(notificationKey(item)));
}

function renderNotificationCenter() {
    const unread = unreadNotifications();
    if (el.notificationUnreadCount) {
        el.notificationUnreadCount.textContent = unread.length > 99 ? '99+' : String(unread.length);
        el.notificationUnreadCount.classList.toggle('has-unread', unread.length > 0);
    }
    if (el.notificationCenterSubtitle) {
        el.notificationCenterSubtitle.textContent = notificationHistory.length
            ? `${unread.length} unread / ${notificationHistory.length} recent`
            : 'No alerts yet';
    }
    if (!el.notificationList) return;

    if (!notificationHistory.length) {
        el.notificationList.innerHTML = '<div class="notification-empty">No dispatched notifications</div>';
        return;
    }

    el.notificationList.innerHTML = notificationHistory.map(item => {
        const key = notificationKey(item);
        const unreadClass = readNotificationIds.has(key) ? '' : ' is-unread';
        const severity = item.severity || severityFromPriority(item.priority);
        const priority = item.priority || 'info';
        const title = item.threat_classification || `${priority.toUpperCase()} file event`;
        const when = item.timestamp ? new Date(item.timestamp).toLocaleString() : '';
        return `
        <button type="button" class="notification-item${unreadClass}" onclick="openNotificationTarget('${escAttr(item.path || '')}', '${escAttr(key)}')">
            <span class="notification-severity sev-${escAttr(priority)}">${esc(severity)}</span>
            <span class="notification-body">
                <span class="notification-title">${esc(title)}</span>
                <span class="notification-path" title="${esc(item.path || '')}">${esc(shortenPath(item.path || 'Unknown path'))}</span>
                <span class="notification-meta">${esc(item.dispatch_type || 'notification')} · risk ${esc(item.risk_score ?? 0)}/10 · ${esc(when)}</span>
            </span>
        </button>`;
    }).join('');
}

function toggleNotificationCenter(force) {
    notificationCenterOpen = typeof force === 'boolean' ? force : !notificationCenterOpen;
    if (!el.notificationCenter) return;
    el.notificationCenter.hidden = !notificationCenterOpen;
    if (notificationCenterOpen) fetchNotificationHistory();
}

function markNotificationsRead() {
    for (const item of notificationHistory) readNotificationIds.add(notificationKey(item));
    persistReadNotifications();
    renderNotificationCenter();
}

function openNotificationTarget(path, key) {
    if (key) {
        readNotificationIds.add(key);
        persistReadNotifications();
    }
    if (path) {
        const match = allFiles.find(file => file.path === path);
        selectFile(path, match ? match.file_id ?? null : null);
    }
    renderNotificationCenter();
}

function persistReadNotifications() {
    const capped = Array.from(readNotificationIds).slice(-500);
    readNotificationIds = new Set(capped);
    localStorage.setItem('ig_read_notifications', JSON.stringify(capped));
}

async function requestDesktopNotifications() {
    if (!('Notification' in window)) {
        toast('Desktop notifications are not supported in this browser', 'toast-high');
        return;
    }
    desktopNotificationRequested = true;
    const permission = await Notification.requestPermission();
    desktopAlertsEnabled = permission === 'granted';
    localStorage.setItem('ig_desktop_alerts', desktopAlertsEnabled ? '1' : '0');
    if (el.desktopAlerts) el.desktopAlerts.checked = desktopAlertsEnabled;
    toast(
        desktopAlertsEnabled ? 'Desktop notifications enabled' : 'Desktop notifications blocked',
        desktopAlertsEnabled ? 'toast-success' : 'toast-high'
    );
}

/* --- Baseline / File Tree -------------------- */
async function fetchBaseline() {
    try {
        const r = await fetch(`${API}/baseline`);
        allFiles = await r.json();
        const selectedChanged = ensureSelectedFile();
        renderFileList();
        if (selectedChanged && (selectedFilePath || selectedFileId)) {
            fetchFileTimeline(selectedFilePath, selectedFileId);
        }
        if (!allFiles.length) {
            showTimelineEmpty('No monitored files', 'Scan results will appear here');
        }
    } catch (e) {
        console.error('Baseline error', e);
    }
}

function ensureSelectedFile() {
    if (!Array.isArray(allFiles) || !allFiles.length) {
        selectedFilePath = null;
        selectedFileId = null;
        return false;
    }

    const existing = allFiles.find(f => {
        if (selectedFileId != null && f.file_id != null) {
            return Number(f.file_id) === Number(selectedFileId);
        }
        return f.path === selectedFilePath;
    });
    if (existing) {
        selectedFilePath = existing.path;
        selectedFileId = existing.file_id ?? null;
        return false;
    }

    const best = allFiles.slice().sort((a, b) => {
        const severity = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const priA = severity[a.highest_priority || 'info'] ?? 5;
        const priB = severity[b.highest_priority || 'info'] ?? 5;
        if (priA !== priB) return priA - priB;
        return (b.change_count || 0) - (a.change_count || 0);
    })[0];
    selectedFilePath = best ? best.path : null;
    selectedFileId = best ? (best.file_id ?? null) : null;
    return !!selectedFilePath;
}

function renderFileList() {
    const baseFiles = Array.isArray(allFiles) ? allFiles.slice() : [];
    renderFilterCounts(baseFiles);

    let files = baseFiles.slice();

    if (currentFilter !== 'all') {
        files = files.filter(f => f.highest_priority === currentFilter);
    }

    if (searchQuery) {
        const q = searchQuery.toLowerCase();
        files = files.filter(f => (f.path || '').toLowerCase().includes(q));
    }

    el.sidebarCount.textContent = files.length;

    if (!files.length) {
        const message = baseFiles.length
            ? 'No files match the current view'
            : 'No monitored files';
        el.fileList.innerHTML = `<div class="empty-state-sm"><p>${message}</p></div>`;
        return;
    }

    const groups = new Map();

    for (const root of watchedRoots) {
        if (!groups.has(root)) groups.set(root, []);
    }

    for (const file of files) {
        const root = bestMatchingRoot(file.path) || inferFallbackRoot(file.path);
        if (!groups.has(root)) groups.set(root, []);
        groups.get(root).push(file);
    }

    const watchedOrder = watchedRoots.slice();
    const remaining = Array.from(groups.keys())
        .filter(root => !watchedOrder.includes(root))
        .sort((a, b) => a.localeCompare(b));

    const orderedRoots = watchedOrder.concat(remaining);

    const validRoots = new Set(orderedRoots);
    for (const node of Array.from(collapsedTreeNodes)) {
        if (!validRoots.has(node)) collapsedTreeNodes.delete(node);
    }

    const watchedNormalized = new Set(watchedRoots.map(r => normalizePath(r)));

    el.fileList.innerHTML = orderedRoots.map(root => {
        const rootFiles = (groups.get(root) || []).slice().sort((a, b) => {
            return (a.path || '').localeCompare(b.path || '');
        });
        const collapsed = collapsedTreeNodes.has(root);
        const isWatchedRoot = watchedNormalized.has(normalizePath(root));

        const tree = buildPathTree(rootFiles, root);
        const fileMarkup = rootFiles.length
            ? renderPathTree(tree, 0, root, [])
            : '<div class="tree-empty">No matching files in this root.</div>';

        return `
        <div class="tree-root-group">
            <div class="tree-root-head">
                <button class="tree-root-toggle" onclick="toggleTreeRoot('${escAttr(root)}')">
                    <span class="tree-caret ${collapsed ? 'collapsed' : ''}">▾</span>
                    <span class="tree-root-name" title="${esc(root)}">${esc(root)}</span>
                    <span class="tree-root-count">${rootFiles.length}</span>
                </button>
                ${isWatchedRoot ? `<button class="tree-root-stop" onclick="stopWatcherForPath('${escAttr(root)}')">Stop</button>` : ''}
            </div>
            <div class="tree-root-files ${collapsed ? 'is-collapsed' : ''}">
                ${fileMarkup}
            </div>
        </div>`;
    }).join('');
}

function renderFilterCounts(files) {
    if (!el.filterCounts) return;
    const counts = { all: files.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const file of files) {
        const priority = file.highest_priority || 'info';
        if (counts[priority] != null) counts[priority] += 1;
    }
    for (const [key, node] of Object.entries(el.filterCounts)) {
        if (node) node.textContent = String(counts[key] || 0);
    }
}

function buildPathTree(files, root) {
    const tree = {
        dirs: new Map(),
        files: [],
        count: 0,
        priority: 'info'
    };

    for (const file of files) {
        const parts = relativePartsForFile(file.path, root);
        addFileToPathTree(tree, parts, file);
    }

    return tree;
}

function relativePartsForFile(path, root) {
    const normalizedPath = normalizePath(path);
    const normalizedRoot = normalizePath(root);

    let relative = normalizedPath;
    if (normalizedRoot && pathWithinRoot(path, root)) {
        relative = normalizedPath.slice(normalizedRoot.length).replace(/^\/+/, '');
    }

    const parts = relative.split('/').filter(Boolean);
    if (!parts.length) {
        return [fileName(path)];
    }
    return parts;
}

function addFileToPathTree(tree, parts, file) {
    tree.count += 1;
    tree.priority = strongerPriority(tree.priority, file.highest_priority || 'info');

    if (!parts.length) {
        tree.files.push(file);
        return;
    }

    if (parts.length === 1) {
        tree.files.push(file);
        return;
    }

    const dirName = parts[0];
    if (!tree.dirs.has(dirName)) {
        tree.dirs.set(dirName, {
            dirs: new Map(),
            files: [],
            count: 0,
            priority: 'info'
        });
    }

    addFileToPathTree(tree.dirs.get(dirName), parts.slice(1), file);
}

function renderPathTree(tree, depth, root, parts) {
    const safeDepth = Math.max(depth, 0);
    let html = '';

    const dirNames = Array.from(tree.dirs.keys()).sort((a, b) => a.localeCompare(b));
    for (const dirName of dirNames) {
        const child = tree.dirs.get(dirName);
        html += renderDirectoryNode(dirName, child, safeDepth, root, parts.concat(dirName));
    }

    const sortedFiles = tree.files.slice().sort((a, b) => {
        return fileName(a.path).localeCompare(fileName(b.path));
    });
    for (const file of sortedFiles) {
        html += renderFileItem(file, safeDepth);
    }

    return html;
}

function renderDirectoryNode(name, node, depth, root, parts) {
    const key = treeDirKey(root, parts);
    const expanded = searchQuery || expandedTreeDirs.has(key) || directoryContainsSelected(node);
    const priority = node.priority || 'info';
    return `
    <button type="button" class="tree-dir-row" style="--depth:${depth}" onclick="toggleTreeDir('${escAttr(key)}')">
        <span class="tree-caret ${expanded ? '' : 'collapsed'}">▾</span>
        <span class="tree-dir-icon pri-${priority}"></span>
        <span class="tree-dir-label" title="${esc(name)}">${esc(name)}</span>
        <span class="tree-dir-count">${node.count}</span>
    </button>
    <div class="tree-dir-children ${expanded ? '' : 'is-collapsed'}">
        ${renderPathTree(node, depth + 1, root, parts)}
    </div>`;
}

function renderFileItem(f, depth = 0) {
    const sameIdentity = selectedFileId != null && f.file_id != null
        && Number(f.file_id) === Number(selectedFileId);
    const active = (sameIdentity || f.path === selectedFilePath) ? ' file-item-active' : '';
    const priority = f.highest_priority || 'info';
    const priClass = `pri-${priority}`;
    const changes = f.change_count || 0;
    const drifted = f.is_baseline === false;
    const name = fileName(f.path);
    const dir = fileDir(f.path);

    return `
    <div class="file-item tree-file-row${active}${drifted ? ' file-item-drifted' : ''}" style="--depth:${Math.max(depth, 0)}" data-path="${esc(f.path)}" onclick="selectFile('${escAttr(f.path)}', ${f.file_id != null ? Number(f.file_id) : 'null'})">
        <div class="file-item-indicator ${priClass}"></div>
        <div class="file-item-body">
            <div class="file-item-name" title="${esc(f.path)}">${esc(name)}</div>
            <div class="file-item-dir">${esc(dir)}</div>
        </div>
        <div class="file-item-meta">
            ${drifted ? '<span class="file-item-drift" title="Drifted from baseline">MODIFIED</span>' : ''}
            <span class="file-item-badge badge-p-${priority}">${priority.toUpperCase()}</span>
            ${changes > 1 ? `<span class="file-item-changes">${changes} events</span>` : '<span class="file-item-changes">1 event</span>'}
        </div>
    </div>`;
}

function toggleTreeRoot(root) {
    if (collapsedTreeNodes.has(root)) {
        collapsedTreeNodes.delete(root);
    } else {
        collapsedTreeNodes.add(root);
    }
    renderFileList();
}

function toggleTreeDir(key) {
    if (expandedTreeDirs.has(key)) {
        expandedTreeDirs.delete(key);
    } else {
        expandedTreeDirs.add(key);
    }
    renderFileList();
}

function setTreeExpansion(expanded) {
    if (!expanded) {
        expandedTreeDirs.clear();
        renderFileList();
        return;
    }

    const files = currentVisibleFiles();
    const groups = groupFilesByRoot(files);
    for (const [root, rootFiles] of groups.entries()) {
        const tree = buildPathTree(rootFiles, root);
        collectTreeDirKeys(tree, root, [], expandedTreeDirs);
    }
    renderFileList();
}

function currentVisibleFiles() {
    let files = Array.isArray(allFiles) ? allFiles.slice() : [];
    if (currentFilter !== 'all') {
        files = files.filter(f => f.highest_priority === currentFilter);
    }
    if (searchQuery) {
        const q = searchQuery.toLowerCase();
        files = files.filter(f => (f.path || '').toLowerCase().includes(q));
    }
    return files;
}

function groupFilesByRoot(files) {
    const groups = new Map();
    for (const root of watchedRoots) {
        if (!groups.has(root)) groups.set(root, []);
    }
    for (const file of files) {
        const root = bestMatchingRoot(file.path) || inferFallbackRoot(file.path);
        if (!groups.has(root)) groups.set(root, []);
        groups.get(root).push(file);
    }
    return groups;
}

function collectTreeDirKeys(node, root, parts, target) {
    for (const [name, child] of node.dirs.entries()) {
        const childParts = parts.concat(name);
        target.add(treeDirKey(root, childParts));
        collectTreeDirKeys(child, root, childParts, target);
    }
}

function treeDirKey(root, parts) {
    return `${normalizePath(root)}::${parts.join('/')}`;
}

function directoryContainsSelected(node) {
    if (!selectedFilePath && selectedFileId == null) return false;
    for (const file of node.files) {
        if (selectedFileId != null && file.file_id != null && Number(file.file_id) === Number(selectedFileId)) {
            return true;
        }
        if (file.path === selectedFilePath) return true;
    }
    for (const child of node.dirs.values()) {
        if (directoryContainsSelected(child)) return true;
    }
    return false;
}

function filterFileList() {
    searchQuery = el.fileSearch.value.trim();
    renderFileList();
}

function filterFiles(filter, btn) {
    currentFilter = filter;
    el.filterGroup.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    renderFileList();
}

function selectFile(path, fileId = null) {
    selectedFilePath = path;
    selectedFileId = fileId;
    renderFileList();
    fetchFileTimeline(path, fileId);
}

function showTimelineEmpty(title = 'No file selected', message = 'Scan results will appear here') {
    el.timelineContent.style.display = 'none';
    el.timelineEmpty.style.display = 'grid';
    const titleNode = el.timelineEmpty.querySelector('h3');
    const messageNode = el.timelineEmpty.querySelector('p');
    if (titleNode) titleNode.textContent = title;
    if (messageNode) messageNode.textContent = message;
}

/* --- File Timeline -------------------------- */
async function fetchFileTimeline(path, fileId = null) {
    try {
        const params = new URLSearchParams();
        if (fileId != null) params.set('file_id', fileId);
        if (path) params.set('path', path);
        const r = await fetch(`${API}/files/timeline?${params.toString()}`);
        const data = await r.json();
        if (data && data.file_id != null) selectedFileId = data.file_id;
        if (data && data.baseline && data.baseline.path) selectedFilePath = data.baseline.path;
        renderTimeline(data);
    } catch (e) {
        console.error('Timeline error', e);
    }
}

function renderTimeline(data) {
    el.timelineEmpty.style.display = 'none';
    el.timelineContent.style.display = 'block';

    const baseline = data.baseline;
    const events = data.events || [];

    const name = fileName((baseline && baseline.path) || selectedFilePath);
    const dir = fileDir((baseline && baseline.path) || selectedFilePath);
    el.timelineHeader.innerHTML = `
        <div class="tl-header-info">
            <h2 class="tl-header-name">${esc(name)}</h2>
            <span class="tl-header-path" title="${esc((baseline && baseline.path) || selectedFilePath)}">${esc(dir)}</span>
        </div>
        <div class="tl-header-stats">
            ${baseline ? `<span class="tl-stat"><strong>${events.length}</strong> events</span>
            <span class="tl-stat">Size: <strong>${baseline.size != null ? fmtSize(baseline.size) : '-'}</strong></span>
            <span class="tl-stat">Hash: <code>${baseline.hash ? baseline.hash.substring(0, 16) + '...' : '-'}</code></span>` : ''}
        </div>
    `;

    if (!events.length) {
        el.timelineTrack.innerHTML = '<div class="tl-empty"><p>No events recorded for this file yet.</p></div>';
        return;
    }

    el.timelineTrack.innerHTML = events.map((ev, idx) => {
        const isBaseline = idx === 0 && ev.event_type === 'new' && baseline && baseline.is_baseline;
        const pri = ev.priority || 'pending';
        const dt = new Date(ev.timestamp);
        const time = dt.toLocaleString([], {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });

        let riskHtml = '';
        if (ev.risk_score != null) {
            const rc = ev.risk_score >= 8 ? 'risk-high' : ev.risk_score >= 4 ? 'risk-med' : 'risk-low';
            riskHtml = `<span class="risk-circle ${rc}" title="Risk score: ${ev.risk_score}">${ev.risk_score}</span>`;
        }

        let hashHtml = '';
        if (ev.old_hash || ev.new_hash) {
            const oldHash = ev.old_hash ? `<span class="hash-old">${ev.old_hash.substring(0, 12)}</span>` : '<span class="hash-none">-</span>';
            const newHash = ev.new_hash ? `<span class="hash-new">${ev.new_hash.substring(0, 12)}</span>` : '<span class="hash-none">-</span>';
            hashHtml = `<div class="tl-hashes">${oldHash}<span class="hash-arrow">-></span>${newHash}</div>`;
        }

        let analysisHtml = '';
        if (ev.analysis && typeof ev.analysis === 'object') {
            const a = ev.analysis;
            const sourceMeta = analysisSourceMeta(a.analysis_source, a.baseline_context);
            const src = sourceMeta.label;
            const srcClass = sourceMeta.className;
            const verdict = analysisVerdict(a, ev);

            const classificationLabel = a.threat_classification
                ? esc(a.threat_classification)
                : (a.threat_type ? esc(a.threat_type.replace(/_/g, ' ')) : 'Analysis Complete');

            let headerHtml = `<div class="analysis-header">
                <div class="analysis-title-block">
                    <span class="analysis-verdict ${verdict.className}">${verdict.label}</span>
                    <span class="analysis-classification">${classificationLabel}</span>
                </div>
                <span class="analysis-source ${srcClass}">${src}</span>
            </div>`;

            let reasoningHtml = '';
            if (a.reasoning) {
                reasoningHtml = `<div class="analysis-reasoning">${esc(a.reasoning)}</div>`;
            }

            let changeHtml = '';
            if (a.change_summary) {
                let changeText = '';
                if (typeof a.change_summary === 'string') {
                    changeText = a.change_summary;
                } else if (a.change_summary.previous_snippet_available) {
                    changeText = `${a.change_summary.added_lines || 0} line(s) added, ${a.change_summary.removed_lines || 0} line(s) removed`;
                }
                if (changeText) {
                    changeHtml = `<div class="analysis-change-summary">${esc(changeText)}</div>`;
                }
            }

            let detailRows = '';

            if (a.threat_type && a.threat_type !== 'benign') {
                detailRows += `<div class="analysis-detail-row">
                    <span class="analysis-detail-label">Threat Type</span>
                    <span class="analysis-detail-value">${esc(a.threat_type.replace(/_/g, ' '))}</span>
                </div>`;
            }

            if (a.confidence) {
                const confClass = a.confidence === 'high' ? 'conf-high' : a.confidence === 'medium' ? 'conf-med' : 'conf-low';
                detailRows += `<div class="analysis-detail-row">
                    <span class="analysis-detail-label">Confidence</span>
                    <span class="analysis-detail-value analysis-conf ${confClass}">${esc(a.confidence)}</span>
                </div>`;
            }

            if (a.mitre_attack && a.mitre_attack.length > 0) {
                const mitreTags = a.mitre_attack
                    .map(t => `<span class="analysis-tag tag-mitre">${esc(t)}</span>`)
                    .join('');
                detailRows += `<div class="analysis-detail-row">
                    <span class="analysis-detail-label">MITRE ATT&CK</span>
                    <div class="analysis-tags">${mitreTags}</div>
                </div>`;
            }

            if (a.iocs && a.iocs.length > 0) {
                const iocTags = a.iocs
                    .map(i => `<span class="analysis-tag tag-ioc">${esc(i)}</span>`)
                    .join('');
                detailRows += `<div class="analysis-detail-row">
                    <span class="analysis-detail-label">IOCs</span>
                    <div class="analysis-tags">${iocTags}</div>
                </div>`;
            }

            const detailsHtml = detailRows ? `<div class="analysis-details">${detailRows}</div>` : '';

            let actionsHtml = '';
            if (Array.isArray(a.recommended_actions) && a.recommended_actions.length > 0) {
                const actionItems = a.recommended_actions.slice(0, 4)
                    .map(action => `<li>${esc(action)}</li>`)
                    .join('');
                actionsHtml = `<div class="analysis-actions">
                    <div class="analysis-findings-label">Recommended Actions</div>
                    <ul>${actionItems}</ul>
                </div>`;
            }

            let findingsHtml = '';
            if (a.findings && a.findings.length > 0) {
                const findingItems = a.findings.slice(0, 5).map(f => {
                    const sevClass = f.severity >= 8 ? 'sev-crit' : f.severity >= 5 ? 'sev-med' : 'sev-low';
                    return `<div class="analysis-finding">
                        <span class="finding-severity ${sevClass}">${f.severity}</span>
                        <span class="finding-category">${esc((f.category || '').replace(/_/g, ' '))}</span>
                        <span class="finding-desc">${esc(f.description)}</span>
                        ${f.matches > 1 ? `<span class="finding-count">x${f.matches}</span>` : ''}
                    </div>`;
                }).join('');
                findingsHtml = `<div class="analysis-findings">
                    <div class="analysis-findings-label">Matched Indicators</div>
                    ${findingItems}
                </div>`;
            }

            const maliciousBorder = a.is_malicious ? ' analysis-malicious' : '';
            analysisHtml = `<div class="tl-analysis tl-analysis-rich${maliciousBorder}">
                ${headerHtml}${changeHtml}${reasoningHtml}${detailsHtml}${actionsHtml}${findingsHtml}
            </div>`;
        } else if (ev.analysis && typeof ev.analysis === 'string') {
            analysisHtml = `<div class="tl-analysis tl-analysis-rich"><div class="analysis-reasoning">${esc(ev.analysis)}</div></div>`;
        } else if (ev.status === 'pending') {
            analysisHtml = '<div class="tl-analysis tl-analysis-pending"><span class="spinner"></span> Analysis pending...</div>';
        }

        const nodeClass = isBaseline ? 'tl-node tl-node-baseline' : `tl-node tl-node-${pri}`;
        const label = isBaseline ? 'BASELINE' : (ev.event_type || '').toUpperCase();
        const badgeClass = isBaseline ? 'badge-baseline' : `badge-${ev.event_type}`;

        return `
        <div class="${nodeClass}" onclick="this.classList.toggle('expanded')">
            <div class="tl-node-dot">
                <div class="tl-dot ${isBaseline ? 'tl-dot-baseline' : `tl-dot-${pri}`}"></div>
                ${idx < events.length - 1 ? '<div class="tl-connector"></div>' : ''}
            </div>
            <div class="tl-node-card">
                <div class="tl-node-top">
                    <span class="badge ${badgeClass}">${label}</span>
                    <span class="badge badge-priority badge-p-${pri}">${pri.toUpperCase()}</span>
                    ${riskHtml}
                    <span class="tl-node-time">${time}</span>
                </div>
                <div class="tl-node-body">
                    <div class="tl-node-details">${esc(ev.details || '')}</div>
                    ${hashHtml}
                    ${analysisHtml}
                </div>
            </div>
        </div>`;
    }).join('');
}

function analysisSourceMeta(source, baselineContext = false) {
    const normalized = (source || '').toLowerCase();
    if (baselineContext || normalized === 'baseline') {
        return { label: 'Baseline', className: 'src-baseline' };
    }
    if (['llm', 'ollama', 'gemini'].includes(normalized)) {
        return { label: 'Model', className: 'src-llm' };
    }
    if (normalized === 'heuristic') {
        return { label: 'Rules', className: 'src-heuristic' };
    }
    return { label: 'Analysis', className: 'src-heuristic' };
}

function analysisVerdict(analysis, event) {
    const score = Number(analysis.risk_score ?? event.risk_score ?? 0);
    if (analysis.is_malicious || score >= 8) {
        return { label: 'Action needed', className: 'verdict-critical' };
    }
    if (score >= 4 || ['medium', 'high'].includes(event.priority)) {
        return { label: 'Review', className: 'verdict-review' };
    }
    if (analysis.baseline_context) {
        return { label: 'Baseline logged', className: 'verdict-logged' };
    }
    return { label: 'Logged', className: 'verdict-logged' };
}

/* --- Actions -------------------------------- */
async function triggerScan() {
    const path = el.scanPath.value.trim();
    if (!path) {
        feedback('Please enter a directory path.', 'error');
        return;
    }

    const reanalyzeExisting = !!(el.reanalyzeExisting && el.reanalyzeExisting.checked);
    feedback(reanalyzeExisting ? 'Starting scan with reanalysis...' : 'Starting scan...', 'info');
    try {
        const r = await fetch(`${API}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path, reanalyze_existing: reanalyzeExisting })
        });

        if (r.ok) {
            const msg = reanalyzeExisting
                ? 'Scan and reanalysis started. Results will appear as files are processed.'
                : 'Hash-first scan started. File hashes will appear before deeper analysis.';
            feedback(msg, 'ok');
            toast('Hash capture started', 'toast-success');
            fetchScanStatus();
        } else {
            const e = await parseApiPayload(r);
            feedback(e.detail || 'Error starting scan', 'error');
        }
    } catch (e) {
        feedback('Connection error: ' + e.message, 'error');
    }
}

async function startWatcher() {
    const path = el.scanPath.value.trim();
    if (!path) {
        feedback('Enter a path first.', 'error');
        return;
    }

    const reanalyzeExisting = !!(el.reanalyzeExisting && el.reanalyzeExisting.checked);
    try {
        const r = await fetch(`${API}/initialize-watch`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path, reanalyze_existing: reanalyzeExisting })
        });

        if (r.ok) {
            const msg = reanalyzeExisting
                ? 'Watcher activated. Baseline reanalysis in progress.'
                : 'Watcher activated. Hash-first baseline started.';
            feedback(msg, 'ok');
            toast('Watcher + init started', 'toast-success');
            fetchWatcherStatus();
            fetchScanStatus();
        } else {
            const e = await parseApiPayload(r);
            feedback(e.detail || 'Failed to start watcher', 'error');
        }
    } catch (e) {
        feedback(e.message, 'error');
    }
}

async function stopWatcher() {
    try {
        const r = await fetch(`${API}/watch/stop`, { method: 'POST' });
        const d = await parseApiPayload(r);
        if (r.ok) {
            feedback(d.message || 'Watcher stopped.', 'info');
            toast(d.message || 'Watcher stopped', 'toast-success');
            fetchWatcherStatus();
            fetchSystemMonitorStatus();
        }
    } catch (e) {
        feedback(e.message, 'error');
    }
}

/* --- Toast Alerts --------------------------- */
function toast(msg, cls = 'toast-success') {
    const t = document.createElement('div');
    t.className = `toast ${cls}`;
    t.textContent = msg;
    el.toastContainer.appendChild(t);
    setTimeout(() => {
        if (t.parentNode) t.remove();
    }, 5000);
}

/* --- Helpers -------------------------------- */
async function parseApiPayload(response) {
    const raw = await response.text();
    if (!raw) return {};
    try {
        return JSON.parse(raw);
    } catch (_err) {
        return { detail: raw };
    }
}

function feedback(text, kind) {
    const colors = {
        ok: 'var(--success-text)',
        error: 'var(--critical-text)',
        info: 'var(--text-muted)'
    };
    el.scanStatus.textContent = text;
    el.scanStatus.style.color = colors[kind] || 'var(--text-muted)';
    setTimeout(() => {
        if (el.scanStatus.textContent === text) {
            el.scanStatus.textContent = '';
        }
    }, 6000);
}

function normalizePath(p) {
    return (p || '').replace(/\\/g, '/').replace(/\/+$/, '');
}

function pathWithinRoot(path, root) {
    const nPath = normalizePath(path).toLowerCase();
    const nRoot = normalizePath(root).toLowerCase();
    if (!nPath || !nRoot) return false;
    return nPath === nRoot || nPath.startsWith(`${nRoot}/`);
}

function bestMatchingRoot(path) {
    let best = null;
    for (const root of watchedRoots) {
        if (!pathWithinRoot(path, root)) continue;
        if (!best || normalizePath(root).length > normalizePath(best).length) {
            best = root;
        }
    }
    return best;
}

function inferFallbackRoot(path) {
    const n = normalizePath(path);
    if (!n) return 'Other';

    if (/^[A-Za-z]:\//.test(n)) {
        const parts = n.split('/');
        if (parts.length >= 2) return `${parts[0]}/${parts[1]}`;
        return parts[0];
    }

    if (n.startsWith('/')) {
        const parts = n.split('/').filter(Boolean);
        return parts.length ? `/${parts[0]}` : '/';
    }

    return fileDir(path) || 'Other';
}

function priorityRank(priority) {
    const ranks = { critical: 5, high: 4, medium: 3, low: 2, info: 1, pending: 0 };
    return ranks[(priority || 'info').toLowerCase()] ?? 1;
}

function strongerPriority(a, b) {
    return priorityRank(b) > priorityRank(a) ? b : a;
}

function severityFromPriority(priority) {
    const normalized = (priority || 'info').toLowerCase();
    if (normalized === 'critical') return 'SEV-1';
    if (normalized === 'high') return 'SEV-2';
    if (normalized === 'medium') return 'SEV-3';
    if (normalized === 'low') return 'SEV-4';
    return 'SEV-5';
}

function shortenPath(p) {
    if (!p) return '-';
    const parts = p.replace(/\\/g, '/').split('/');
    return parts.length > 2 ? `.../${parts.slice(-2).join('/')}` : p;
}

function fileName(p) {
    if (!p) return '-';
    const parts = p.replace(/\\/g, '/').split('/');
    return parts[parts.length - 1] || p;
}

function fileDir(p) {
    if (!p) return '';
    const parts = p.replace(/\\/g, '/').split('/');
    if (parts.length <= 1) return '';
    return parts.length > 3
        ? `.../${parts.slice(-3, -1).join('/')}`
        : parts.slice(0, -1).join('/');
}

function fmtSize(b) {
    if (b === 0) return '0 B';
    const k = 1024;
    const s = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + s[i];
}

function fmtDuration(seconds) {
    const safe = Math.max(0, Number(seconds) || 0);
    if (safe < 1) return `${Math.round(safe * 1000)} ms`;
    if (safe < 60) return `${safe.toFixed(1)} s`;
    const mins = Math.floor(safe / 60);
    const secs = Math.round(safe % 60);
    return `${mins}m ${String(secs).padStart(2, '0')}s`;
}

function esc(t) {
    if (!t) return '';
    const d = document.createElement('div');
    d.textContent = t;
    return d.innerHTML;
}

function escAttr(t) {
    return (t || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}
