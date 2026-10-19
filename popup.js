// popup.js - Complete Secure Authenticator UI Controller

// ===== DOM REFS =====
const DOM = {
    // Screens
    setupPassword: document.getElementById('setupPasswordScreen'),
    setupRecovery: document.getElementById('setupRecoveryScreen'),
    lockScreen: document.getElementById('lockScreen'),
    forgotScreen: document.getElementById('forgotScreen'),
    resetScreen: document.getElementById('resetScreen'),
    mainScreen: document.getElementById('mainScreen'),
    settingsScreen: document.getElementById('settingsScreen'),

    // Header
    statusBadge: document.getElementById('statusBadge'),
    accountCount: document.getElementById('accountCount'),

    // Setup Password
    setupPwd: document.getElementById('setupPwd'),
    setupPwd2: document.getElementById('setupPwd2'),
    setupPwdBtn: document.getElementById('setupPwdBtn'),
    setupPwdError: document.getElementById('setupPwdError'),

    // Setup Recovery
    recoveryQ1: document.getElementById('recoveryQ1'),
    recoveryQ2: document.getElementById('recoveryQ2'),
    recoveryQ3: document.getElementById('recoveryQ3'),
    setupRecoveryBtn: document.getElementById('setupRecoveryBtn'),
    setupRecoveryError: document.getElementById('setupRecoveryError'),

    // Lock Screen
    lockPwd: document.getElementById('lockPwd'),
    unlockBtn: document.getElementById('unlockBtn'),
    lockError: document.getElementById('lockError'),
    forgotBtn: document.getElementById('forgotBtn'),

    // Forgot Password
    forgotQ1: document.getElementById('forgotQ1'),
    forgotQ2: document.getElementById('forgotQ2'),
    forgotQ3: document.getElementById('forgotQ3'),
    forgotVerifyBtn: document.getElementById('forgotVerifyBtn'),
    forgotCancelBtn: document.getElementById('forgotCancelBtn'),
    forgotError: document.getElementById('forgotError'),

    // Reset Password
    resetPwd: document.getElementById('resetPwd'),
    resetPwd2: document.getElementById('resetPwd2'),
    resetBtn: document.getElementById('resetBtn'),
    resetCancelBtn: document.getElementById('resetCancelBtn'),
    resetError: document.getElementById('resetError'),

    // Settings
    settingsBackBtn: document.getElementById('settingsBackBtn'),
    timeoutMinutes: document.getElementById('timeoutMinutes'),
    timeoutSeconds: document.getElementById('timeoutSeconds'),
    saveTimeoutBtn: document.getElementById('saveTimeoutBtn'),
    timeoutStatus: document.getElementById('timeoutStatus'),
    exportBackupBtn: document.getElementById('exportBackupBtn'),
    exportStatus: document.getElementById('exportStatus'),
    importBackupBtn: document.getElementById('importBackupBtn'),
    importFileInput: document.getElementById('importFileInput'),
    importStatus: document.getElementById('importStatus'),
    restoreBackupBtn: document.getElementById('restoreBackupBtn'),
    showAccountCountLocked: document.getElementById('showAccountCountLocked'),
    accountCountStatus: document.getElementById('accountCountStatus'),

    // File preview
    selectedFileCard: document.getElementById('selectedFileCard'),
    selectedFileName: document.getElementById('selectedFileName'),
    selectedFileMeta: document.getElementById('selectedFileMeta'),
    removeSelectedFile: document.getElementById('removeSelectedFile'),

    // Main Screen
    accountName: document.getElementById('accountName'),
    accountSecret: document.getElementById('accountSecret'),
    addAccountBtn: document.getElementById('addAccountBtn'),
    accountList: document.getElementById('accountList'),
    testBtn: document.getElementById('testBtn'),
    lockBtn: document.getElementById('lockBtn'),
    settingsBtn: document.getElementById('settingsBtn'),
    statusBar: document.getElementById('statusBar'),

    // Edit Modal
    editModal: document.getElementById('editModal'),
    editModalTitle: document.getElementById('editModalTitle'),
    editModalClose: document.getElementById('editModalClose'),
    editAccountName: document.getElementById('editAccountName'),
    editAccountSecret: document.getElementById('editAccountSecret'),
    editAccountDescription: document.getElementById('editAccountDescription'),
    editError: document.getElementById('editError'),
    editModalCancel: document.getElementById('editModalCancel'),
    editModalSave: document.getElementById('editModalSave'),

    // Auto-Lock Toggle
    autoLockToggle: document.getElementById('autoLockToggle'),
    timeoutSection: document.getElementById('timeoutSection'),
};

// ===== STATE =====
let state = {
    accounts: {},
    locked: true,
    setupComplete: false,
    updateInterval: null,
    sessionRemaining: 300,
    totalAccountCount: 0,
    showAccountCountWhenLocked: true,
    timerDisplayInterval: null,
    autoLockEnabled: true,
};

// ===== EDIT STATE =====
let editingAccountName = null;
let accountDescriptions = {};

// ===== DRAG STATE =====
let draggedAccountName = null;
let dragStartIndex = -1;

// ===== AUTO-LOCK CONFIGURATION =====
let AUTO_LOCK_CONFIG = {
    enabled: true,
    timeoutSeconds: 300,
};

// ===== TOTP PERIOD =====
const TOTP_PERIOD = 60;

// ===== SECURITY: Password Hashing =====
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function verifyPassword(inputPassword, storedHash) {
    const inputHash = await hashPassword(inputPassword);
    return inputHash === storedHash;
}

// ===== SECURITY: Clear Secrets from Memory =====
function clearSecretsFromMemory() {
    for (const key in state.accounts) {
        if (typeof state.accounts[key] === 'string') {
            const len = state.accounts[key].length;
            state.accounts[key] = 'X'.repeat(len);
        }
    }
    state.accounts = {};
}

// ===== UTILITY FUNCTIONS =====
function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(s => s.classList.add('hidden'));
    const screen = document.getElementById(screenId);
    if (screen) screen.classList.remove('hidden');
}

function updateStatus(message, isError = false) {
    DOM.statusBar.textContent = message;
    DOM.statusBar.style.color = isError ? '#ff4444' : '#88ff88';
}

function updateBadge(locked) {
    if (locked) {
        updateAccountCountLocked();
    } else {
        updateAccountCount();
    }
}

function updateAccountCount() {
    const count = Object.keys(state.accounts).length;
    state.totalAccountCount = count;

    chrome.storage.local.set({ totalAccountCount: count });

    const countText = DOM.accountCount.querySelector('.account-count-text');
    if (countText) {
        countText.textContent = `${count} account${count !== 1 ? 's' : ''}`;
    }
}

function updateAccountCountLocked() {
    if (!state.showAccountCountWhenLocked) {
        const countText = DOM.accountCount.querySelector('.account-count-text');
        if (countText) {
            countText.textContent = '🔒 Hidden';
        }
        return;
    }

    chrome.storage.local.get(['totalAccountCount'], (result) => {
        const count = result.totalAccountCount || 0;
        state.totalAccountCount = count;
        const countText = DOM.accountCount.querySelector('.account-count-text');
        if (countText) {
            countText.textContent = `${count} account${count !== 1 ? 's' : ''}`;
        }
    });
}

function clearErrors() {
    document.querySelectorAll('.error-message').forEach(el => el.textContent = '');
}

function showError(element, message) {
    element.textContent = message;
    setTimeout(() => {
        if (element.textContent === message) {
            element.textContent = '';
        }
    }, 3000);
}

function showSettingsStatus(element, message, type = 'info') {
    element.textContent = message;
    element.className = 'settings-status ' + type;
    setTimeout(() => {
        if (element.textContent === message) {
            element.textContent = '';
            element.className = 'settings-status';
        }
    }, 5000);
}

// ===== TOAST NOTIFICATION =====
function showToast(message, type = 'success', duration = 3000) {
    const toast = document.getElementById('toastNotification');
    if (toast) {
        toast.textContent = message;
        toast.className = 'toast-notification';

        if (type === 'error') {
            toast.classList.add('error');
        } else if (type === 'warning') {
            toast.classList.add('warning');
        } else {
            toast.classList.add('success');
        }

        toast.classList.add('show');

        if (toast._timeout) {
            clearTimeout(toast._timeout);
        }

        toast._timeout = setTimeout(() => {
            toast.classList.remove('show');
        }, duration);
        return;
    }

    const statusBar = DOM.statusBar;
    if (statusBar) {
        statusBar.textContent = message;
        statusBar.style.color = type === 'error' ? '#ff4444' : '#88ff88';
        setTimeout(() => {
            if (statusBar.textContent === message) {
                statusBar.textContent = '✅ Ready';
                statusBar.style.color = '#88ff88';
            }
        }, duration);
    }
}

// ===== COMMUNICATION WITH BACKGROUND =====
function sendMessage(message) {
    return new Promise((resolve, reject) => {
        try {
            chrome.runtime.sendMessage(message, (response) => {
                if (chrome.runtime.lastError) {
                    console.error('Runtime error:', chrome.runtime.lastError);
                    reject(new Error(chrome.runtime.lastError.message));
                } else if (response && response.success) {
                    resolve(response);
                } else if (response && response.error) {
                    reject(new Error(response.error));
                } else {
                    reject(new Error('Unknown error occurred'));
                }
            });
        } catch (error) {
            console.error('Send message error:', error);
            reject(error);
        }
    });
}

// ===== GET SESSION FROM BACKGROUND =====
async function getSessionData() {
    try {
        const response = await sendMessage({ type: 'GET_SESSION' });
        return response;
    } catch (error) {
        console.error('Failed to get session:', error);
        return null;
    }
}

async function updateSessionDisplay() {
    if (state.locked) return;
    if (!state.autoLockEnabled) return;

    const session = await getSessionData();
    if (session) {
        state.sessionRemaining = session.sessionRemaining ?? AUTO_LOCK_CONFIG.timeoutSeconds;

        if (state.sessionRemaining <= 0) {
            state.locked = true;
            updateBadge(true);
            showScreen('lockScreen');
            DOM.lockPwd.value = '';
            DOM.lockPwd.focus();
            updateStatus('🔒 Session expired', true);
            return;
        }

        updateSessionStatus();
    }
}

// ===== TOTP GENERATION =====
class TOTP {
    constructor(secret, digits = 6, period = TOTP_PERIOD) {
        this.secret = secret;
        this.digits = digits;
        this.period = period;
    }

    async generate(timestamp = null) {
        try {
            const response = await sendMessage({
                type: 'GENERATE_CODE',
                payload: { secret: this.secret }
            });
            return response.code;
        } catch (error) {
            return this.generateClientSide(timestamp);
        }
    }

    async generateClientSide(timestamp = null) {
        const t = timestamp || Math.floor(Date.now() / 1000);
        const counter = Math.floor(t / this.period);

        const counterBytes = new ArrayBuffer(8);
        const view = new DataView(counterBytes);
        view.setBigUint64(0, BigInt(counter), false);

        const secretBytes = this.base32Decode(this.secret.toUpperCase());

        const key = await crypto.subtle.importKey(
            'raw',
            secretBytes,
            { name: 'HMAC', hash: 'SHA-1' },
            false,
            ['sign']
        );

        const signature = await crypto.subtle.sign('HMAC', key, counterBytes);

        const hash = new Uint8Array(signature);
        const offset = hash[hash.length - 1] & 0x0F;
        const binary = ((hash[offset] & 0x7F) << 24) |
            ((hash[offset + 1] & 0xFF) << 16) |
            ((hash[offset + 2] & 0xFF) << 8) |
            (hash[offset + 3] & 0xFF);

        const otp = binary % Math.pow(10, this.digits);
        return otp.toString().padStart(this.digits, '0');
    }

    getRemaining() {
        return this.period - (Math.floor(Date.now() / 1000) % this.period);
    }

    base32Decode(encoded) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const bits = [];

        for (const char of encoded) {
            const index = alphabet.indexOf(char);
            if (index === -1) continue;
            for (let i = 4; i >= 0; i--) {
                bits.push((index >> i) & 1);
            }
        }

        const bytes = [];
        for (let i = 0; i + 7 < bits.length; i += 8) {
            let byte = 0;
            for (let j = 0; j < 8; j++) {
                byte = (byte << 1) | bits[i + j];
            }
            bytes.push(byte);
        }

        return new Uint8Array(bytes);
    }
}

// ===== ACCOUNT LIST RENDERING =====
function renderAccounts() {
    DOM.accountList.innerHTML = '';

    const accountNames = Object.keys(state.accounts);
    if (accountNames.length === 0) {
        DOM.accountList.innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">📭</span>
                <p class="empty-text">No accounts</p>
                <p class="empty-subtext">Add your first account above</p>
            </div>
        `;
        return;
    }

    accountNames.forEach((name, index) => {
        const secret = state.accounts[name];
        const totp = new TOTP(secret);
        const description = accountDescriptions[name] || '';

        const item = document.createElement('div');
        item.className = 'account-item';
        item.dataset.name = name;
        item.dataset.index = index;
        item.setAttribute('draggable', 'true');

        item.innerHTML = `
            <div class="account-item-inner">
                <span class="account-drag-handle" title="Drag to reorder">⋮⋮</span>
                <div class="account-info">
                    <span class="account-name">${escapeHTML(name)}</span>
                    ${description ? `<span class="account-description">${escapeHTML(description)}</span>` : ''}
                </div>
                <div class="account-code-group">
                    <span class="account-code account-code-safe">••••••</span>
                    <span class="account-timer">60s</span>
                </div>
                <div class="account-actions">
                    <button class="btn-icon" data-action="copy" title="Copy code">📋</button>
                    <button class="btn-icon btn-edit" data-action="edit" title="Edit">✏️</button>
                    <button class="btn-icon btn-delete" data-action="delete" title="Delete">✕</button>
                </div>
            </div>
        `;

        DOM.accountList.appendChild(item);

        totp.generate().then(code => {
            const codeElement = item.querySelector('.account-code');
            const timerElement = item.querySelector('.account-timer');
            updateCodeDisplay(codeElement, timerElement, code, totp);
        });

        const copyBtn = item.querySelector('[data-action="copy"]');
        const editBtn = item.querySelector('[data-action="edit"]');
        const deleteBtn = item.querySelector('[data-action="delete"]');

        copyBtn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const codeElement = item.querySelector('.account-code');
            const code = codeElement.textContent;

            if (code === '⏰ EXPIRED') {
                showToast('⚠️ Code expired! Wait for new code', 'warning');
                return;
            }

            const success = await copyToClipboard(code);

            if (success) {
                copyBtn.textContent = '✅';
                copyBtn.style.color = '#2ecc71';

                if (copyBtn._resetTimeout) {
                    clearTimeout(copyBtn._resetTimeout);
                }
                copyBtn._resetTimeout = setTimeout(() => {
                    copyBtn.textContent = '📋';
                    copyBtn.style.color = '';
                    copyBtn._resetTimeout = null;
                }, 1500);
            }

            resetSessionTimer();
        });

        editBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            openEditModal(name);
            resetSessionTimer();
        });

        deleteBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            deleteAccount(name);
            resetSessionTimer();
        });

        // Drag events
        item.addEventListener('dragstart', handleDragStart);
        item.addEventListener('dragover', handleDragOver);
        item.addEventListener('dragenter', handleDragEnter);
        item.addEventListener('dragleave', handleDragLeave);
        item.addEventListener('drop', handleDrop);
        item.addEventListener('dragend', handleDragEnd);
    });
}

let previousCodeMap = {};

function updateCodeDisplay(codeElement, timerElement, code, totp) {
    const remaining = totp.getRemaining();
    const codeKey = codeElement.closest('.account-item').dataset.name;

    if (previousCodeMap[codeKey] && code !== previousCodeMap[codeKey]) {
        codeElement.className = 'account-code account-code-danger';
        codeElement.style.animation = 'blink 1s infinite';

        if (codeElement._timeout) {
            clearTimeout(codeElement._timeout);
        }

        codeElement._timeout = setTimeout(() => {
            codeElement.textContent = code;
            codeElement.className = 'account-code';
            codeElement.style.fontSize = '';
            codeElement.style.animation = '';
            updateCodeDisplayInner(codeElement, timerElement, code, totp);
            codeElement._timeout = null;
        }, 1500);
    } else {
        updateCodeDisplayInner(codeElement, timerElement, code, totp);
    }

    previousCodeMap[codeKey] = code;
}

function updateCodeDisplayInner(codeElement, timerElement, code, totp) {
    const remaining = totp.getRemaining();
    codeElement.textContent = code;
    codeElement.className = 'account-code';
    codeElement.style.animation = '';

    if (remaining < 10) {
        codeElement.classList.add('account-code-danger');
        codeElement.style.animation = 'blink 1s infinite';
    } else if (remaining < 20) {
        codeElement.classList.add('account-code-warning');
    } else {
        codeElement.classList.add('account-code-safe');
    }

    timerElement.textContent = `${remaining}s`;
}

function escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ===== COPY TO CLIPBOARD =====
async function copyToClipboard(text) {
    if (text === '⏰ EXPIRED') {
        showToast('⚠️ Code expired! Wait for new code', 'warning');
        return false;
    }

    let success = false;

    try {
        await navigator.clipboard.writeText(text);
        success = true;
    } catch (error) {
        try {
            await sendMessage({
                type: 'COPY_CODE',
                payload: { code: text }
            });
            success = true;
        } catch (e) {
            try {
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
                success = true;
            } catch (err) {
                success = false;
            }
        }
    }

    if (success) {
        showToast(`📋 Copied: ${text}`, 'success');

        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();

            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);

            oscillator.frequency.value = 800;
            oscillator.type = 'sine';

            gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.1);

            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.1);
        } catch (e) { }
    } else {
        showToast('❌ Failed to copy', 'error');
    }

    return success;
}

// ===== ACCOUNT OPERATIONS =====
async function addAccount(name, secret) {
    if (name === undefined || secret === undefined) {
        name = DOM.accountName.value.trim();
        secret = DOM.accountSecret.value.trim().toUpperCase();
    }

    if (!name) {
        updateStatus('❌ Please enter an account name', true);
        if (DOM.accountName) DOM.accountName.focus();
        return false;
    }

    if (!secret) {
        updateStatus('❌ Please enter a secret key', true);
        if (DOM.accountSecret) DOM.accountSecret.focus();
        return false;
    }

    if (!/^[A-Z2-7]+$/.test(secret.replace(/\s/g, ''))) {
        updateStatus('❌ Invalid secret format (Base32)', true);
        if (DOM.accountSecret) {
            DOM.accountSecret.value = '';
            DOM.accountSecret.focus();
        }
        return false;
    }

    try {
        const response = await sendMessage({
            type: 'ADD_ACCOUNT',
            payload: { name, secret }
        });

        state.accounts = response.accounts;
        renderAccounts();
        updateAccountCount();
        updateStatus(`✅ Added: ${name}`);
        resetSessionTimer();

        if (DOM.accountName) DOM.accountName.value = '';
        if (DOM.accountSecret) DOM.accountSecret.value = '';
        if (DOM.accountName) DOM.accountName.focus();

        return true;
    } catch (error) {
        updateStatus(`❌ ${error.message}`, true);
        return false;
    }
}

async function deleteAccount(name) {
    if (!await customConfirm(`Delete "${name}"?`)) return;

    try {
        const response = await sendMessage({
            type: 'DELETE_ACCOUNT',
            payload: { name }
        });

        state.accounts = response.accounts;
        delete accountDescriptions[name];
        renderAccounts();
        updateAccountCount();
        updateStatus(`🗑️ Deleted: ${name}`);
        resetSessionTimer();
    } catch (error) {
        updateStatus(`❌ ${error.message}`, true);
    }
}

// ===== DRAG AND DROP =====
function handleDragStart(e) {
    const item = e.currentTarget || e.target.closest('.account-item');
    if (!item) return;

    draggedAccountName = item.dataset.name;
    dragStartIndex = Object.keys(state.accounts).indexOf(draggedAccountName);

    item.classList.add('dragging');

    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', draggedAccountName);

    try {
        e.dataTransfer.setDragImage(item, 20, 20);
    } catch (err) { }

    updateStatus(`📦 Moving: ${draggedAccountName}`);
}

function handleDragOver(e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';

    const item = e.currentTarget || e.target.closest('.account-item');
    if (!item || !draggedAccountName) return;

    const targetName = item.dataset.name;
    if (targetName === draggedAccountName) return;

    document.querySelectorAll('.account-item').forEach(el => {
        el.classList.remove('drag-over', 'drag-over-top', 'drag-over-bottom');
    });

    const rect = item.getBoundingClientRect();
    const midpoint = rect.top + rect.height / 2;
    const isTopHalf = e.clientY < midpoint;

    if (isTopHalf) {
        item.classList.add('drag-over-top');
    } else {
        item.classList.add('drag-over-bottom');
    }

    item.classList.add('drag-over');
}

function handleDragEnter(e) {
    e.preventDefault();
}

function handleDragLeave(e) {
    const item = e.currentTarget || e.target.closest('.account-item');
    if (!item) return;

    if (!item.contains(e.relatedTarget)) {
        item.classList.remove('drag-over', 'drag-over-top', 'drag-over-bottom');
    }
}

async function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();

    const item = e.currentTarget || e.target.closest('.account-item');
    if (!item || !draggedAccountName) {
        clearDragState();
        return;
    }

    const targetName = item.dataset.name;

    document.querySelectorAll('.account-item').forEach(el => {
        el.classList.remove('dragging', 'drag-over', 'drag-over-top', 'drag-over-bottom');
    });

    if (targetName === draggedAccountName) {
        clearDragState();
        return;
    }

    try {
        const currentOrder = Object.keys(state.accounts);
        const fromIndex = currentOrder.indexOf(draggedAccountName);
        const toIndex = currentOrder.indexOf(targetName);

        if (fromIndex === -1 || toIndex === -1) {
            clearDragState();
            return;
        }

        const rect = item.getBoundingClientRect();
        const midpoint = rect.top + rect.height / 2;
        const isTopHalf = e.clientY < midpoint;

        const newOrder = [...currentOrder];
        newOrder.splice(fromIndex, 1);

        let insertIndex = toIndex;
        if (fromIndex < toIndex) {
            insertIndex = isTopHalf ? toIndex - 1 : toIndex;
        } else {
            insertIndex = isTopHalf ? toIndex : toIndex + 1;
        }

        insertIndex = Math.max(0, Math.min(newOrder.length, insertIndex));

        newOrder.splice(insertIndex, 0, draggedAccountName);

        const response = await sendMessage({
            type: 'REORDER_ACCOUNTS',
            payload: { orderedNames: newOrder }
        });

        state.accounts = response.accounts;
        renderAccounts();

        updateStatus(`✅ Moved "${draggedAccountName}" to position ${insertIndex + 1}`);
        showToast(`📦 Moved to position ${insertIndex + 1}`, 'success');

        resetSessionTimer();

    } catch (error) {
        console.error('Drop error:', error);
        updateStatus(`❌ ${error.message}`, true);
        showToast(`❌ ${error.message}`, 'error');
        renderAccounts();
    }

    clearDragState();
}

function handleDragEnd(e) {
    document.querySelectorAll('.account-item').forEach(el => {
        el.classList.remove('dragging', 'drag-over', 'drag-over-top', 'drag-over-bottom');
    });
    clearDragState();
}

function clearDragState() {
    draggedAccountName = null;
    dragStartIndex = -1;
    document.querySelectorAll('.account-item').forEach(el => {
        el.classList.remove('dragging', 'drag-over', 'drag-over-top', 'drag-over-bottom');
    });
}

function customConfirm(message) {
    return new Promise((resolve) => {
        const modal = document.createElement("div");

        modal.innerHTML = `
            <div class="custom-confirm-overlay">
                <div class="custom-confirm">
                    <h3>Confirm Delete</h3>
                    <p>${message}</p>

                    <div class="custom-confirm-buttons">
                        <button class="cancel-btn">Cancel</button>
                        <button class="delete-btn">Delete</button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        const close = (result) => {
            modal.remove();
            resolve(result);
        };

        modal.querySelector(".cancel-btn").onclick = () => close(false);
        modal.querySelector(".delete-btn").onclick = () => close(true);
    });
}

// ===== CUSTOM 3-CHOICE MODAL =====
function custom3Choice(message, title = 'Confirm') {
    return new Promise((resolve) => {
        const modal = document.createElement('div');

        modal.innerHTML = `
            <div class="custom-confirm-overlay">
                <div class="custom-confirm">
                    <h3>${title}</h3>
                    <p style="white-space: pre-line; margin-bottom: 20px; color: #b8c5d6; font-size: 12px;">${message}</p>

                    <div class="custom-confirm-buttons" style="flex-direction: column; gap: 8px;">
                        <button class="replace-btn" style="background: linear-gradient(95deg, #e74c3c, #c0392b); color: white; padding: 10px 18px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; width: 100%;">🔄 Replace All</button>
                        <button class="merge-btn" style="background: linear-gradient(95deg, #2ecc71, #27ae60); color: white; padding: 10px 18px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; width: 100%;">➕ Merge (Add Missing)</button>
                        <button class="cancel-btn" style="background: #3d3d3d; color: white; padding: 10px 18px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; width: 100%;">✕ Cancel</button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        const close = (result) => {
            modal.remove();
            resolve(result);
        };

        modal.querySelector('.replace-btn').onclick = () => close('replace');
        modal.querySelector('.merge-btn').onclick = () => close('merge');
        modal.querySelector('.cancel-btn').onclick = () => close('cancel');

        modal.querySelector('.custom-confirm-overlay').addEventListener('click', (e) => {
            if (e.target === modal.querySelector('.custom-confirm-overlay')) {
                close('cancel');
            }
        });

        const escHandler = (e) => {
            if (e.key === 'Escape') {
                document.removeEventListener('keydown', escHandler);
                close('cancel');
            }
        };
        document.addEventListener('keydown', escHandler);
    });
}

// ===== EDIT ACCOUNT MODAL =====
function openEditModal(name) {
    if (state.locked) return;

    const secret = state.accounts[name];
    if (!secret) return;

    editingAccountName = name;

    DOM.editModalTitle.textContent = `✏️ Edit "${name}"`;
    DOM.editAccountName.value = name;
    DOM.editAccountSecret.value = secret;
    DOM.editAccountDescription.value = accountDescriptions[name] || '';
    DOM.editError.textContent = '';

    DOM.editModal.classList.add('active');

    setTimeout(() => DOM.editAccountName.focus(), 100);
}

function closeEditModal() {
    DOM.editModal.classList.remove('active');
    editingAccountName = null;
    DOM.editError.textContent = '';
}

async function saveEditModal() {
    if (!editingAccountName) return;

    const newName = DOM.editAccountName.value.trim();
    const newSecret = DOM.editAccountSecret.value.trim().toUpperCase();
    const newDescription = DOM.editAccountDescription.value.trim();

    DOM.editError.textContent = '';

    if (!newName) {
        DOM.editError.textContent = '❌ Account name cannot be empty';
        DOM.editAccountName.focus();
        return;
    }

    if (!newSecret) {
        DOM.editError.textContent = '❌ Secret key cannot be empty';
        DOM.editAccountSecret.focus();
        return;
    }

    if (!/^[A-Z2-7]+$/.test(newSecret.replace(/\s/g, ''))) {
        DOM.editError.textContent = '❌ Invalid secret format (Base32)';
        DOM.editAccountSecret.focus();
        return;
    }

    if (newName !== editingAccountName && state.accounts[newName] !== undefined) {
        DOM.editError.textContent = '❌ An account with that name already exists';
        DOM.editAccountName.focus();
        return;
    }

    const oldName = editingAccountName;

    try {
        const response = await sendMessage({
            type: 'UPDATE_ACCOUNT',
            payload: {
                name: oldName,
                newName: newName,
                secret: newSecret,
                description: newDescription
            }
        });

        state.accounts = response.accounts;

        if (newName !== oldName) {
            delete accountDescriptions[oldName];
        }
        if (newDescription) {
            accountDescriptions[newName] = newDescription;
        } else {
            delete accountDescriptions[newName];
        }

        renderAccounts();
        updateAccountCount();
        closeEditModal();

        let msg = `✅ Updated "${newName}"`;
        if (newName !== oldName) {
            msg = `✅ Renamed "${oldName}" → "${newName}"`;
        }
        updateStatus(msg);
        showToast(msg, 'success');

        resetSessionTimer();

    } catch (error) {
        DOM.editError.textContent = `❌ ${error.message}`;
    }
}

// ===== UPDATE CODES PERIODICALLY =====
function startCodeUpdates() {
    if (state.updateInterval) {
        clearInterval(state.updateInterval);
        state.updateInterval = null;
    }

    state.updateInterval = setInterval(() => {
        if (!state.locked && Object.keys(state.accounts).length > 0) {
            document.querySelectorAll('.account-item').forEach(item => {
                const name = item.dataset.name;
                if (name && state.accounts[name]) {
                    const secret = state.accounts[name];
                    const totp = new TOTP(secret);
                    const codeElement = item.querySelector('.account-code');
                    const timerElement = item.querySelector('.account-timer');

                    totp.generate().then(code => {
                        updateCodeDisplay(codeElement, timerElement, code, totp);
                    });
                }
            });
        }
    }, 1000);
}

// ===== SESSION MANAGEMENT =====
function startTimerDisplay() {
    if (state.timerDisplayInterval) {
        clearInterval(state.timerDisplayInterval);
        state.timerDisplayInterval = null;
    }

    updateSessionDisplay();

    state.timerDisplayInterval = setInterval(() => {
        if (!state.locked) {
            updateSessionDisplay();
        }
    }, 1000);
}

function updateSessionStatus() {
    if (state.locked) return;

    if (!state.autoLockEnabled) {
        updateStatus('🔓 Unlocked (manual lock only)');
        return;
    }

    const total = state.sessionRemaining;

    if (total <= 0) {
        updateStatus('🔴 Session expired!', true);
        return;
    }

    const mins = Math.floor(total / 60);
    const secs = total % 60;

    if (total > 120) {
        updateStatus(`🔓 Session: ${mins}m ${secs.toString().padStart(2, '0')}s remaining`);
    } else if (total > 60) {
        updateStatus(`⚠️ Session: ${mins}m ${secs.toString().padStart(2, '0')}s remaining`);
    } else if (total > 10) {
        updateStatus(`🔴 Session: ${total}s remaining!`);
    } else if (total > 0) {
        updateStatus(`🚨 Session expires in ${total}s!`, true);
    }
}

async function resetSessionTimer() {
    if (state.locked) return;

    try {
        const response = await sendMessage({ type: 'RESET_SESSION_TIMER' });
        if (response && response.success) {
            state.sessionRemaining = response.sessionRemaining ?? AUTO_LOCK_CONFIG.timeoutSeconds;
            updateSessionStatus();
        }
    } catch (error) {
        console.error('Failed to reset session:', error);
    }
}

function cleanupTimers() {
    if (state.updateInterval) {
        clearInterval(state.updateInterval);
        state.updateInterval = null;
    }
    if (state.timerDisplayInterval) {
        clearInterval(state.timerDisplayInterval);
        state.timerDisplayInterval = null;
    }
}

// ===== SETTINGS FUNCTIONS =====
function showSettings() {
    showScreen('settingsScreen');

    // Re-sync the toggle to match current state (no flash, already loaded)
    if (DOM.autoLockToggle) {
        DOM.autoLockToggle.checked = state.autoLockEnabled;
    }

    // Re-sync the timeout inputs
    if (DOM.timeoutMinutes && DOM.timeoutSeconds) {
        const total = AUTO_LOCK_CONFIG.timeoutSeconds;
        DOM.timeoutMinutes.value = Math.floor(total / 60);
        DOM.timeoutSeconds.value = total % 60;
    }

    // Update gray-out state
    updateTimeoutSectionState();
}

function loadSettings() {
    chrome.storage.local.get(
        [
            'timeoutMinutes',
            'timeoutSeconds',
            'timeoutTotalSeconds',
            'showAccountCountWhenLocked',
            'autoLockEnabled'
        ],
        (result) => {
            const autoLockEnabled = result.autoLockEnabled !== undefined
                ? result.autoLockEnabled
                : true;

            state.autoLockEnabled = autoLockEnabled;
            AUTO_LOCK_CONFIG.enabled = autoLockEnabled;

            if (DOM.autoLockToggle) {
                DOM.autoLockToggle.checked = autoLockEnabled;
            }

            let minutes = 1;
            let seconds = 0;

            if (result.timeoutTotalSeconds !== undefined && result.timeoutTotalSeconds >= 30) {
                const total = result.timeoutTotalSeconds;
                minutes = Math.floor(total / 60);
                seconds = total % 60;
            } else if (result.timeoutMinutes !== undefined || result.timeoutSeconds !== undefined) {
                minutes = result.timeoutMinutes !== undefined ? result.timeoutMinutes : 1;
                seconds = result.timeoutSeconds !== undefined ? result.timeoutSeconds : 0;
            }

            DOM.timeoutMinutes.value = minutes;
            DOM.timeoutSeconds.value = seconds;

            const total = (minutes * 60) + seconds;
            if (total >= 30) {
                AUTO_LOCK_CONFIG.timeoutSeconds = total;
            }

            const showCount = result.showAccountCountWhenLocked !== undefined
                ? result.showAccountCountWhenLocked
                : true;
            if (DOM.showAccountCountLocked) {
                DOM.showAccountCountLocked.checked = showCount;
            }
            state.showAccountCountWhenLocked = showCount;

            updateTimeoutSectionState();
        }
    );
}

async function saveTimeout() {
    let minutes = parseInt(DOM.timeoutMinutes.value);
    let seconds = parseInt(DOM.timeoutSeconds.value);

    if (isNaN(minutes)) minutes = 0;
    if (isNaN(seconds)) seconds = 0;

    if (minutes < 0 || minutes > 60) {
        showSettingsStatus(DOM.timeoutStatus, '❌ Minutes must be between 0 and 60', 'error');
        showToast('❌ Minutes must be between 0 and 60', 'error');
        return;
    }
    if (seconds < 0 || seconds > 59) {
        showSettingsStatus(DOM.timeoutStatus, '❌ Seconds must be between 0 and 59', 'error');
        showToast('❌ Seconds must be between 0 and 59', 'error');
        return;
    }

    const totalSeconds = (minutes * 60) + seconds;
    if (totalSeconds < 30) {
        showSettingsStatus(DOM.timeoutStatus, '⚠️ Timeout must be at least 30 seconds', 'info');
        showToast('⚠️ Timeout must be at least 30 seconds', 'warning');
        return;
    }

    try {
        AUTO_LOCK_CONFIG.timeoutSeconds = totalSeconds;

        const response = await sendMessage({
            type: 'SAVE_TIMEOUT',
            payload: {
                minutes: minutes,
                seconds: seconds,
                totalSeconds: totalSeconds
            }
        });

        if (!response || !response.success) {
            throw new Error(response?.error || 'Failed to save timeout');
        }

        await new Promise((resolve) => {
            chrome.storage.local.set({
                timeoutMinutes: minutes,
                timeoutSeconds: seconds,
                timeoutTotalSeconds: totalSeconds
            }, resolve);
        });

        if (!state.locked && response.sessionRemaining !== undefined) {
            state.sessionRemaining = response.sessionRemaining;
            updateSessionStatus();
        }

        let displayMessage = '';
        if (minutes === 0 && seconds > 0) {
            displayMessage = `${seconds} seconds`;
        } else if (minutes > 0 && seconds === 0) {
            displayMessage = `${minutes} minute${minutes > 1 ? 's' : ''}`;
        } else if (minutes > 0 && seconds > 0) {
            displayMessage = `${minutes}m ${seconds}s`;
        } else {
            displayMessage = '0 seconds (disabled)';
        }

        showSettingsStatus(DOM.timeoutStatus, `✅ Timeout saved: ${displayMessage}`, 'success');
        showToast(`✅ Timeout saved: ${displayMessage}`, 'success');

    } catch (error) {
        console.error('❌ Save timeout error:', error);
        showSettingsStatus(DOM.timeoutStatus, `❌ Failed to save: ${error.message}`, 'error');
        showToast(`❌ Failed to save: ${error.message}`, 'error');
    }
}

// ===== AUTO-LOCK TOGGLE =====
async function handleAutoLockToggle(enabled) {
    state.autoLockEnabled = enabled;
    AUTO_LOCK_CONFIG.enabled = enabled;
    updateTimeoutSectionState();

    if (enabled) {
        showToast('🔐 Auto-lock enabled', 'success');
    } else {
        showToast('🔓 Auto-lock disabled', 'warning');
    }

    try {
        await new Promise((resolve) => {
            chrome.storage.local.set({ autoLockEnabled: enabled }, resolve);
        });

        const response = await sendMessage({
            type: 'TOGGLE_AUTO_LOCK',
            payload: { enabled }
        });

        if (!response || !response.success) {
            throw new Error(response?.error || 'Failed to toggle auto-lock');
        }

        if (!state.locked) {
            if (enabled) {
                startTimerDisplay();
            } else {
                if (state.timerDisplayInterval) {
                    clearInterval(state.timerDisplayInterval);
                    state.timerDisplayInterval = null;
                }
                updateStatus('🔓 Unlocked (manual lock only)');
            }
        }
    } catch (error) {
        console.error('❌ Toggle auto-lock error:', error);

        state.autoLockEnabled = !enabled;
        AUTO_LOCK_CONFIG.enabled = !enabled;
        if (DOM.autoLockToggle) {
            DOM.autoLockToggle.checked = !enabled;
        }
        updateTimeoutSectionState();

        showToast(`❌ ${error.message}`, 'error');
    }
}

function updateTimeoutSectionState() {
    if (!DOM.timeoutSection) return;

    const isEnabled = DOM.autoLockToggle ? DOM.autoLockToggle.checked : state.autoLockEnabled;

    if (isEnabled) {
        DOM.timeoutSection.classList.remove('disabled');
    } else {
        DOM.timeoutSection.classList.add('disabled');
    }
}

// ===== BACKUP FUNCTIONS =====
async function exportBackup() {
    if (state.locked) {
        showSettingsStatus(DOM.exportStatus, '❌ Extension is locked. Please unlock first.', 'error');
        return;
    }

    try {
        const accounts = state.accounts;

        let freshDescriptions = {};
        try {
            const descResponse = await sendMessage({ type: 'GET_DESCRIPTIONS' });
            freshDescriptions = descResponse.descriptions || {};
            accountDescriptions = freshDescriptions;
        } catch (e) {
            freshDescriptions = accountDescriptions || {};
        }

        const mergedAccounts = {};
        for (const [name, secret] of Object.entries(accounts)) {
            mergedAccounts[name] = {
                secret: secret,
                description: freshDescriptions[name] || ''
            };
        }

        const backupData = {
            version: '2.0',
            timestamp: new Date().toISOString(),
            accounts: mergedAccounts,
            accountCount: Object.keys(accounts).length,
            type: 'auth_accounts_backup'
        };

        const jsonString = JSON.stringify(backupData, null, 2);

        const blob = new Blob([jsonString], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        const date = new Date().toISOString().slice(0, 10);
        const filename = `auth_accounts_backup_${date}.json`;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 5000);

        const descCount = Object.values(mergedAccounts).filter(a => a.description).length;

        showSettingsStatus(DOM.exportStatus,
            `✅ Backup exported! (${Object.keys(accounts).length} accounts, ${descCount} with descriptions)`,
            'success');
        showToast(`📤 Exported ${Object.keys(accounts).length} accounts`);
    } catch (error) {
        console.error('❌ Export error:', error);
        showSettingsStatus(DOM.exportStatus, `❌ Export failed: ${error.message}`, 'error');
        showToast(`❌ Export failed: ${error.message}`, true);
    }
}

function handleFileSelected(event) {
    const file = event.target.files[0];

    if (!file) {
        hideSelectedFileCard();
        DOM.restoreBackupBtn.disabled = true;
        return;
    }

    if (!file.name.toLowerCase().endsWith('.json')) {
        showSettingsStatus(DOM.importStatus, '⚠️ Please select a .json backup file', 'error');
        showToast('⚠️ Please select a .json backup file', 'error');
        hideSelectedFileCard();
        DOM.restoreBackupBtn.disabled = true;
        event.target.value = '';
        return;
    }

    const sizeInKB = file.size / 1024;
    let sizeText;
    if (sizeInKB < 1) sizeText = `${file.size} B`;
    else if (sizeInKB < 1024) sizeText = `${sizeInKB.toFixed(1)} KB`;
    else sizeText = `${(sizeInKB / 1024).toFixed(2)} MB`;

    const modified = new Date(file.lastModified);
    const now = new Date();
    const diffMs = now - modified;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    let timeAgo;
    if (diffMins < 1) timeAgo = 'just now';
    else if (diffMins < 60) timeAgo = `${diffMins}m ago`;
    else if (diffHours < 24) timeAgo = `${diffHours}h ago`;
    else if (diffDays < 7) timeAgo = `${diffDays}d ago`;
    else timeAgo = modified.toLocaleDateString();

    DOM.selectedFileName.textContent = file.name;
    DOM.selectedFileName.title = file.name;
    DOM.selectedFileMeta.textContent = `${sizeText} · Modified ${timeAgo}`;

    DOM.selectedFileCard.style.display = 'flex';
    DOM.restoreBackupBtn.disabled = false;

    DOM.importStatus.textContent = '';
    DOM.importStatus.className = 'settings-status';

    showToast(`📂 Selected: ${file.name}`, 'success');
}

function hideSelectedFileCard() {
    DOM.selectedFileCard.style.display = 'none';
    DOM.selectedFileName.textContent = '';
    DOM.selectedFileMeta.textContent = '';
    DOM.importFileInput.value = '';
}

async function restoreBackup() {
    const fileInput = DOM.importFileInput;
    const file = fileInput.files[0];

    if (!file) {
        showSettingsStatus(DOM.importStatus, '❌ Please select a backup file first', 'error');
        return;
    }

    if (state.locked) {
        showSettingsStatus(DOM.importStatus, '❌ Extension is locked. Please unlock first.', 'error');
        return;
    }

    try {
        const text = await file.text();

        let backupData;
        try {
            backupData = JSON.parse(text);
        } catch (e) {
            throw new Error(`Invalid JSON file: ${e.message}`);
        }

        if (!backupData.accounts || typeof backupData.accounts !== 'object') {
            throw new Error('Invalid backup: missing "accounts" object');
        }

        const accountKeys = Object.keys(backupData.accounts);
        if (accountKeys.length === 0) {
            throw new Error('No accounts found in backup');
        }

        let validAccounts = {};
        let parsedDescriptions = {};
        let invalidAccounts = [];

        const isNewFormat = typeof Object.values(backupData.accounts)[0] === 'object';

        for (const [name, value] of Object.entries(backupData.accounts)) {
            if (isNewFormat) {
                if (value && typeof value === 'object' && typeof value.secret === 'string') {
                    const secret = value.secret.trim().toUpperCase();
                    if (name.trim() && /^[A-Z2-7]+$/.test(secret.replace(/\s/g, ''))) {
                        validAccounts[name] = secret;
                        if (value.description && value.description.trim()) {
                            parsedDescriptions[name] = value.description.trim();
                        }
                    } else {
                        invalidAccounts.push(name);
                    }
                } else {
                    invalidAccounts.push(name);
                }
            } else {
                if (typeof name === 'string' && typeof value === 'string' && name.trim() && value.trim()) {
                    const secret = value.trim().toUpperCase();
                    if (/^[A-Z2-7]+$/.test(secret.replace(/\s/g, ''))) {
                        validAccounts[name] = secret;
                    } else {
                        invalidAccounts.push(name);
                    }
                } else {
                    invalidAccounts.push(name);
                }
            }
        }

        if (!isNewFormat && backupData.descriptions) {
            parsedDescriptions = backupData.descriptions;
        }

        if (Object.keys(validAccounts).length === 0) {
            throw new Error('No valid accounts found in backup');
        }

        const currentCount = Object.keys(state.accounts).length;
        const backupCount = Object.keys(validAccounts).length;
        const descCount = Object.keys(parsedDescriptions).length;

        const summary = `Backup contains ${backupCount} valid accounts` +
            (descCount > 0 ? ` and ${descCount} descriptions` : '') + `.\n` +
            `Current list has ${currentCount} accounts.`;

        const choice = await custom3Choice(summary, '📥 Restore Backup');

        if (choice === 'cancel') {
            showToast('❌ Restore cancelled', 'info');
            return;
        }

        const replace = (choice === 'replace');

        let addedCount = 0;
        let skippedCount = 0;
        let descRestored = 0;

        if (replace) {
            const currentAccounts = Object.keys(state.accounts);
            for (const name of currentAccounts) {
                try {
                    await sendMessage({
                        type: 'DELETE_ACCOUNT',
                        payload: { name }
                    });
                } catch (e) { }
            }

            state.accounts = {};
            accountDescriptions = {};

            for (const [name, secret] of Object.entries(validAccounts)) {
                const success = await addAccount(name, secret);
                if (success) {
                    addedCount++;

                    const desc = parsedDescriptions[name];
                    if (desc && desc.trim()) {
                        try {
                            await sendMessage({
                                type: 'UPDATE_ACCOUNT',
                                payload: {
                                    name: name,
                                    newName: name,
                                    secret: secret,
                                    description: desc
                                }
                            });
                            accountDescriptions[name] = desc;
                            descRestored++;
                        } catch (e) {
                            console.warn(`Description restore failed for ${name}:`, e);
                        }
                    }
                } else {
                    skippedCount++;
                }
                await new Promise(r => setTimeout(r, 100));
            }

            showToast(`✅ Replaced with ${addedCount} accounts (${descRestored} descriptions)`);
        } else {
            for (const [name, secret] of Object.entries(validAccounts)) {
                if (!state.accounts[name]) {
                    const success = await addAccount(name, secret);
                    if (success) {
                        addedCount++;

                        const desc = parsedDescriptions[name];
                        if (desc && desc.trim()) {
                            try {
                                await sendMessage({
                                    type: 'UPDATE_ACCOUNT',
                                    payload: {
                                        name: name,
                                        newName: name,
                                        secret: secret,
                                        description: desc
                                    }
                                });
                                accountDescriptions[name] = desc;
                                descRestored++;
                            } catch (e) {
                                console.warn(`Description restore failed for ${name}:`, e);
                            }
                        }
                    } else {
                        skippedCount++;
                    }
                    await new Promise(r => setTimeout(r, 100));
                } else {
                    skippedCount++;
                }
            }

            showToast(`✅ Added ${addedCount} accounts (${descRestored} descriptions)`);
        }

        try {
            const freshAccounts = await sendMessage({ type: 'GET_ACCOUNTS' });
            state.accounts = freshAccounts.accounts || {};

            const freshDesc = await sendMessage({ type: 'GET_DESCRIPTIONS' });
            accountDescriptions = freshDesc.descriptions || {};
        } catch (e) {
            console.warn('Could not refresh state:', e);
        }

        renderAccounts();
        updateAccountCount();
        updateStatus(`✅ Restored ${addedCount} accounts (${skippedCount} skipped)`);
        showSettingsStatus(DOM.importStatus,
            `✅ Backup restored! Added ${addedCount} accounts, ${descRestored} descriptions`,
            'success');

        hideSelectedFileCard();
        DOM.restoreBackupBtn.disabled = true;

    } catch (error) {
        console.error('❌ Restore error:', error);
        showSettingsStatus(DOM.importStatus, `❌ Restore failed: ${error.message}`, 'error');
        showToast(`❌ Restore failed: ${error.message}`, true);
    }
}

// ===== SCREEN NAVIGATION =====
async function handleSetupPassword() {
    const pwd = DOM.setupPwd.value;
    const pwd2 = DOM.setupPwd2.value;

    clearErrors();

    if (!pwd) {
        showError(DOM.setupPwdError, '❌ Password cannot be empty');
        DOM.setupPwd.focus();
        return;
    }

    if (pwd.length < 6) {
        showError(DOM.setupPwdError, '❌ Password must be 6+ characters');
        DOM.setupPwd.focus();
        return;
    }

    if (pwd !== pwd2) {
        showError(DOM.setupPwdError, '❌ Passwords do not match');
        DOM.setupPwd2.value = '';
        DOM.setupPwd2.focus();
        return;
    }

    try {
        const hashedPassword = await hashPassword(pwd);

        await sendMessage({
            type: 'SETUP_PASSWORD',
            payload: { password: hashedPassword }
        });

        DOM.setupPwd.value = '';
        DOM.setupPwd2.value = '';
        DOM.setupPwdError.textContent = '';

        showScreen('setupRecoveryScreen');
        DOM.recoveryQ1.focus();
    } catch (error) {
        showError(DOM.setupPwdError, `❌ ${error.message}`);
    }
}

async function handleSetupRecovery() {
    const answers = [
        DOM.recoveryQ1.value,
        DOM.recoveryQ2.value,
        DOM.recoveryQ3.value
    ];

    clearErrors();

    if (answers.some(a => !a || a.trim() === '')) {
        showError(DOM.setupRecoveryError, '❌ Please answer all 3 questions');
        return;
    }

    try {
        const response = await sendMessage({
            type: 'SETUP_RECOVERY',
            payload: { answers }
        });

        state.locked = false;
        state.accounts = {};
        state.sessionRemaining = AUTO_LOCK_CONFIG.timeoutSeconds;
        accountDescriptions = {};
        updateBadge(false);
        updateAccountCount();

        showScreen('mainScreen');
        updateStatus('✅ Setup complete! Add your first account');
        renderAccounts();
        startCodeUpdates();
        startTimerDisplay();
        DOM.accountName.focus();

    } catch (error) {
        showError(DOM.setupRecoveryError, `❌ ${error.message}`);
    }
}

async function handleUnlock() {
    const password = DOM.lockPwd.value;
    DOM.lockError.textContent = '';

    if (!password) {
        showError(DOM.lockError, '❌ Please enter your password');
        DOM.lockPwd.focus();
        return;
    }

    try {
        const storedHash = await new Promise((resolve) => {
            chrome.storage.local.get(['password'], (result) => {
                resolve(result.password);
            });
        });

        const isValid = await verifyPassword(password, storedHash);
        if (!isValid) {
            throw new Error('Wrong password');
        }

        const response = await sendMessage({
            type: 'UNLOCK',
            payload: { password: storedHash }
        });

        state.locked = false;
        state.accounts = response.accounts;
        state.sessionRemaining = response.sessionRemaining ?? AUTO_LOCK_CONFIG.timeoutSeconds;

        try {
            const descResponse = await sendMessage({ type: 'GET_DESCRIPTIONS' });
            accountDescriptions = descResponse.descriptions || {};
        } catch (e) {
            accountDescriptions = {};
        }

        updateBadge(false);
        updateAccountCount();

        showScreen('mainScreen');
        renderAccounts();
        startCodeUpdates();
        startTimerDisplay();
        DOM.accountName.focus();

        DOM.lockPwd.value = '';
    } catch (error) {
        showError(DOM.lockError, `❌ ${error.message}`);
        DOM.lockPwd.value = '';
        DOM.lockPwd.focus();
    }
}

async function handleLock() {
    try {
        const currentCount = Object.keys(state.accounts).length;
        state.totalAccountCount = currentCount;

        await new Promise((resolve) => {
            chrome.storage.local.set({ totalAccountCount: currentCount }, resolve);
        });

        cleanupTimers();
        clearSecretsFromMemory();

        state.locked = true;

        updateAccountCountLocked();
        updateBadge(true);
        showScreen('lockScreen');
        DOM.lockPwd.value = '';
        DOM.lockPwd.focus();
        DOM.lockError.textContent = '';
        updateStatus('🔒 Locked');

        await sendMessage({ type: 'LOCK' });
    } catch (error) {
        updateStatus(`❌ ${error.message}`, true);
    }
}

function showForgotScreen() {
    showScreen('forgotScreen');
    DOM.forgotQ1.value = '';
    DOM.forgotQ2.value = '';
    DOM.forgotQ3.value = '';
    DOM.forgotError.textContent = '';
    DOM.forgotQ1.focus();
}

async function handleForgotVerify() {
    const answers = [
        DOM.forgotQ1.value,
        DOM.forgotQ2.value,
        DOM.forgotQ3.value
    ];

    DOM.forgotError.textContent = '';

    if (answers.some(a => !a || a.trim() === '')) {
        showError(DOM.forgotError, '❌ Please answer all 3 questions');
        return;
    }

    try {
        await sendMessage({
            type: 'FORGOT_PASSWORD',
            payload: { answers }
        });

        showScreen('resetScreen');
        DOM.resetPwd.value = '';
        DOM.resetPwd2.value = '';
        DOM.resetError.textContent = '';
        DOM.resetPwd.focus();
    } catch (error) {
        showError(DOM.forgotError, `❌ ${error.message}`);
        DOM.forgotQ1.value = '';
        DOM.forgotQ2.value = '';
        DOM.forgotQ3.value = '';
        DOM.forgotQ1.focus();
    }
}

async function handleResetPassword() {
    const pwd = DOM.resetPwd.value;
    const pwd2 = DOM.resetPwd2.value;

    DOM.resetError.textContent = '';

    if (!pwd || pwd.length < 6) {
        showError(DOM.resetError, '❌ Password must be 6+ characters');
        DOM.resetPwd.focus();
        return;
    }

    if (pwd !== pwd2) {
        showError(DOM.resetError, '❌ Passwords do not match');
        DOM.resetPwd2.value = '';
        DOM.resetPwd2.focus();
        return;
    }

    try {
        const hashedPassword = await hashPassword(pwd);

        await sendMessage({
            type: 'RESET_PASSWORD',
            payload: { newPassword: hashedPassword }
        });

        state.locked = false;
        state.sessionRemaining = AUTO_LOCK_CONFIG.timeoutSeconds;
        updateBadge(false);
        showScreen('mainScreen');
        updateStatus('✅ Password reset successfully!');
        renderAccounts();
        startCodeUpdates();
        startTimerDisplay();

        DOM.resetPwd.value = '';
        DOM.resetPwd2.value = '';
        DOM.resetError.textContent = '';
    } catch (error) {
        showError(DOM.resetError, `❌ ${error.message}`);
    }
}

async function addTestAccount() {
    if (state.locked) return;
    await addAccount('Google Test', 'JBSWY3DPEHPK3PXP');
}

// ===== POPUP VISIBILITY HANDLING =====
document.addEventListener('visibilitychange', function () {
    if (document.hidden) {
        console.log('👋 Popup hidden - timer continues in background');
    } else {
        console.log('👀 Popup visible - updating UI');
        if (!state.locked) {
            updateSessionDisplay();
            renderAccounts();
        } else {
            updateAccountCountLocked();
        }
    }
});

// ===== INITIALIZATION =====
async function initialize() {
    try {
        const result = await new Promise((resolve) => {
            chrome.storage.local.get([
                'timeoutMinutes',
                'timeoutSeconds',
                'timeoutTotalSeconds',
                'totalAccountCount',
                'showAccountCountWhenLocked',
                'autoLockEnabled'
            ], resolve);
        });

        console.log('📋 Loaded from storage:', result);

        // ⭐ Load timeout
        let totalSeconds;
        if (result.timeoutTotalSeconds !== undefined && result.timeoutTotalSeconds >= 30) {
            totalSeconds = result.timeoutTotalSeconds;
        } else if (result.timeoutMinutes !== undefined || result.timeoutSeconds !== undefined) {
            const minutes = result.timeoutMinutes !== undefined ? result.timeoutMinutes : 1;
            const seconds = result.timeoutSeconds !== undefined ? result.timeoutSeconds : 0;
            totalSeconds = (minutes * 60) + seconds;
        } else {
            totalSeconds = 60;
        }

        if (totalSeconds < 30) totalSeconds = 30;

        AUTO_LOCK_CONFIG.timeoutSeconds = totalSeconds;

        // ⭐ Load auto-lock toggle state
        state.autoLockEnabled = result.autoLockEnabled !== undefined
            ? result.autoLockEnabled
            : true;
        AUTO_LOCK_CONFIG.enabled = state.autoLockEnabled;

        console.log(`⏰ Auto-lock timeout: ${AUTO_LOCK_CONFIG.timeoutSeconds} seconds`);
        console.log(`🔐 Auto-lock enabled: ${state.autoLockEnabled}`);

        // ⭐ Sync the toggle checkbox NOW (before user ever opens Settings)
        if (DOM.autoLockToggle) {
            DOM.autoLockToggle.checked = state.autoLockEnabled;
            console.log('✅ Auto-lock toggle checkbox set to:', state.autoLockEnabled);
        }

        // ⭐ Sync the timeout inputs NOW
        if (DOM.timeoutMinutes && DOM.timeoutSeconds) {
            if (result.timeoutTotalSeconds !== undefined && result.timeoutTotalSeconds >= 30) {
                DOM.timeoutMinutes.value = Math.floor(result.timeoutTotalSeconds / 60);
                DOM.timeoutSeconds.value = result.timeoutTotalSeconds % 60;
            } else {
                DOM.timeoutMinutes.value = result.timeoutMinutes !== undefined ? result.timeoutMinutes : 1;
                DOM.timeoutSeconds.value = result.timeoutSeconds !== undefined ? result.timeoutSeconds : 0;
            }
            console.log('✅ Timeout inputs set:', DOM.timeoutMinutes.value + 'm', DOM.timeoutSeconds.value + 's');
        }

        // ⭐ Sync the account count toggle NOW
        state.showAccountCountWhenLocked = result.showAccountCountWhenLocked !== undefined
            ? result.showAccountCountWhenLocked
            : true;
        if (DOM.showAccountCountLocked) {
            DOM.showAccountCountLocked.checked = state.showAccountCountWhenLocked;
        }

        // ⭐ Update the timeout section gray-out state NOW
        updateTimeoutSectionState();

        // ⭐ Load from background
        const response = await sendMessage({ type: 'INIT' });

        state.setupComplete = response.state !== 'setup';
        state.locked = response.locked || false;
        state.totalAccountCount = result.totalAccountCount || 0;

        if (!state.setupComplete) {
            showScreen('setupPasswordScreen');
            DOM.setupPwd.focus();
            updateBadge(true);
            document.body.classList.remove('initializing');
            document.body.classList.add('initialized');
            return;
        }

        updateBadge(state.locked);

        if (!state.locked) {
            // ⭐ Check if background thinks it's unlocked but has no accounts
            // This happens when browser was closed and password was lost
            const expectedCount = result.totalAccountCount || 0;

            const accountsResponse = await sendMessage({ type: 'GET_ACCOUNTS' });
            state.accounts = accountsResponse.accounts || {};
            const actualCount = Object.keys(state.accounts).length;

            console.log(`📊 Expected accounts: ${expectedCount}, Actual: ${actualCount}`);

            // ⭐ If we expect accounts but got none, we need to lock
            if (expectedCount > 0 && actualCount === 0) {
                console.log('⚠️ Account mismatch — forcing lock (browser was closed)');

                state.locked = true;
                state.accounts = {};

                await sendMessage({ type: 'LOCK' });

                updateAccountCountLocked();
                showScreen('lockScreen');
                DOM.lockPwd.focus();
                updateStatus('🔒 Please enter your password', true);

                document.body.classList.remove('initializing');
                document.body.classList.add('initialized');
                return;
            }

            state.sessionRemaining = response.sessionRemaining ?? AUTO_LOCK_CONFIG.timeoutSeconds;

            try {
                const descResponse = await sendMessage({ type: 'GET_DESCRIPTIONS' });
                accountDescriptions = descResponse.descriptions || {};
            } catch (e) {
                accountDescriptions = {};
            }

            updateAccountCount();
            showScreen('mainScreen');
            renderAccounts();
            startCodeUpdates();

            if (state.autoLockEnabled) {
                startTimerDisplay();
            } else {
                updateStatus('🔓 Unlocked (manual lock only)');
            }

            DOM.accountName.focus();
        } else {
            updateAccountCountLocked();
            showScreen('lockScreen');
            DOM.lockPwd.focus();
            updateStatus('🔒 Locked');
        }

        document.body.classList.remove('initializing');
        document.body.classList.add('initialized');

    } catch (error) {
        console.error('Initialization error:', error);
        updateStatus(`❌ Failed to initialize: ${error.message}`, true);
        showScreen('lockScreen');
        DOM.lockPwd.focus();

        document.body.classList.remove('initializing');
        document.body.classList.add('initialized');
    }
}

// ===== EVENT LISTENERS =====
document.addEventListener('DOMContentLoaded', initialize);

// Setup Password
DOM.setupPwd.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') DOM.setupPwd2.focus();
});
DOM.setupPwd2.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleSetupPassword();
});
DOM.setupPwdBtn.addEventListener('click', handleSetupPassword);

// Setup Recovery
DOM.recoveryQ1.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') DOM.recoveryQ2.focus();
});
DOM.recoveryQ2.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') DOM.recoveryQ3.focus();
});
DOM.recoveryQ3.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleSetupRecovery();
});
DOM.setupRecoveryBtn.addEventListener('click', handleSetupRecovery);

// Lock Screen
DOM.lockPwd.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleUnlock();
});
DOM.unlockBtn.addEventListener('click', handleUnlock);
DOM.forgotBtn.addEventListener('click', showForgotScreen);

// Forgot Password
DOM.forgotQ1.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') DOM.forgotQ2.focus();
});
DOM.forgotQ2.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') DOM.forgotQ3.focus();
});
DOM.forgotQ3.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleForgotVerify();
});
DOM.forgotVerifyBtn.addEventListener('click', handleForgotVerify);
DOM.forgotCancelBtn.addEventListener('click', () => {
    showScreen('lockScreen');
    DOM.lockPwd.focus();
});

// Reset Password
DOM.resetPwd.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') DOM.resetPwd2.focus();
});
DOM.resetPwd2.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleResetPassword();
});
DOM.resetBtn.addEventListener('click', handleResetPassword);
DOM.resetCancelBtn.addEventListener('click', () => {
    showScreen('lockScreen');
    DOM.lockPwd.focus();
});

// Settings
DOM.settingsBtn.addEventListener('click', showSettings);
DOM.settingsBackBtn.addEventListener('click', () => {
    showScreen('mainScreen');
    updateStatus('✅ Ready');
});
DOM.saveTimeoutBtn.addEventListener('click', saveTimeout);
DOM.exportBackupBtn.addEventListener('click', exportBackup);
DOM.importBackupBtn.addEventListener('click', () => {
    DOM.importFileInput.click();
});
DOM.importFileInput.addEventListener('change', handleFileSelected);
DOM.restoreBackupBtn.addEventListener('click', restoreBackup);

// Remove selected file
if (DOM.removeSelectedFile) {
    DOM.removeSelectedFile.addEventListener('click', () => {
        hideSelectedFileCard();
        DOM.restoreBackupBtn.disabled = true;
        DOM.importStatus.textContent = '';
        DOM.importStatus.className = 'settings-status';
        showToast('🗑️ File removed', 'info');
    });
}

// ⭐ AUTO-LOCK TOGGLE — This is the fix!
if (DOM.autoLockToggle) {
    DOM.autoLockToggle.addEventListener('change', function () {
        handleAutoLockToggle(this.checked);
    });
}

// Account Count Toggle
if (DOM.showAccountCountLocked) {
    DOM.showAccountCountLocked.addEventListener('change', function () {
        const showCount = this.checked;
        state.showAccountCountWhenLocked = showCount;
        chrome.storage.local.set({ showAccountCountWhenLocked: showCount });

        if (state.locked) {
            if (showCount) {
                updateAccountCountLocked();
            } else {
                const countText = DOM.accountCount.querySelector('.account-count-text');
                if (countText) {
                    countText.textContent = '🔒 Hidden';
                }
            }
        }

        showSettingsStatus(DOM.accountCountStatus, showCount ? '✅ Account count visible when locked' : '🔒 Account count hidden when locked', 'success');
    });
}

// Main Screen
DOM.accountName.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') DOM.accountSecret.focus();
    resetSessionTimer();
});
DOM.accountSecret.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        addAccount();
        resetSessionTimer();
    }
});
DOM.addAccountBtn.addEventListener('click', () => {
    addAccount();
    resetSessionTimer();
});
DOM.testBtn.addEventListener('click', () => {
    addTestAccount();
    resetSessionTimer();
});
DOM.lockBtn.addEventListener('click', handleLock);

// Edit Modal
DOM.editModalClose.addEventListener('click', closeEditModal);
DOM.editModalCancel.addEventListener('click', closeEditModal);
DOM.editAccountName.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') DOM.editAccountSecret.focus();
});
DOM.editAccountSecret.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') DOM.editAccountDescription.focus();
});
DOM.editModal.addEventListener('click', (e) => {
    if (e.target === DOM.editModal) {
        closeEditModal();
    }
});
DOM.editModalSave.addEventListener('click', saveEditModal);

// Click events to reset timer
document.addEventListener('click', () => {
    if (!state.locked) {
        resetSessionTimer();
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
        e.preventDefault();
        if (!state.locked) handleLock();
    }
    if (e.key === 'Escape') {
        if (DOM.editModal.classList.contains('active')) {
            closeEditModal();
        } else if (state.locked) {
            if (!DOM.forgotScreen.classList.contains('hidden')) {
                showScreen('lockScreen');
            } else if (!DOM.resetScreen.classList.contains('hidden')) {
                showScreen('lockScreen');
            } else if (!DOM.settingsScreen.classList.contains('hidden')) {
                showScreen('mainScreen');
            }
        }
    }
    if (!state.locked) {
        resetSessionTimer();
    }
});

console.log('🔐 Secure Authenticator popup loaded');
console.log(`⏰ Auto-lock timeout: ${AUTO_LOCK_CONFIG.timeoutSeconds} seconds`);
console.log(`🔄 TOTP period: ${TOTP_PERIOD} seconds`);
console.log('📦 Backup: Accounts + descriptions (MERGED)');
console.log('⏱️ Timer runs in background service worker');
console.log('🎯 No flash initialization enabled');
console.log('🔐 Auto-lock toggle listener: ATTACHED');