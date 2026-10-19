// background.js - Service Worker for Secure Authenticator Extension
// Cross-browser compatible: Chrome, Edge, Firefox, Opera, etc.

// ===== CROSS-BROWSER COMPATIBILITY =====
const EXT = globalThis.browser || globalThis.chrome || globalThis.browser;

// ===== CONSTANTS =====
const STORAGE_KEYS = {
  ACCOUNTS: 'accounts',
  PASSWORD: 'password',
  SESSION_PASSWORD: 'sessionPassword',
  RECOVERY: 'recovery',
  IS_SETUP: 'isSetup',
  LOCKED: 'locked',
  LAST_STATE: 'lastState',
  SESSION_EXPIRES_AT: 'sessionExpiresAt',
  TIMEOUT_SECONDS: 'timeoutSeconds',
  TIMEOUT_MINUTES: 'timeoutMinutes',
  TIMEOUT_TOTAL_SECONDS: 'timeoutTotalSeconds',
  ACCOUNT_DESCRIPTIONS: 'accountDescriptions',
  AUTO_LOCK_ENABLED: 'autoLockEnabled'
};

// ===== STATE =====
let currentState = {
  locked: true,
  password: null,
  accounts: {},
  recovery: {},
  sessionExpiresAt: null,
  isAutoLocking: false
};

// ===== AUTO-LOCK CONFIGURATION =====
let AUTO_LOCK_CONFIG = {
  enabled: true,
  timeoutSeconds: 300
};

// ===== CROSS-BROWSER STORAGE =====
const storage = {
  get: (keys) => {
    return new Promise((resolve, reject) => {
      try {
        const result = EXT.storage.local.get(keys);
        if (result && typeof result.then === 'function') {
          result.then(resolve).catch(reject);
        } else {
          EXT.storage.local.get(keys, (data) => {
            if (EXT.runtime.lastError) {
              reject(new Error(EXT.runtime.lastError.message));
            } else {
              resolve(data);
            }
          });
        }
      } catch (error) {
        reject(error);
      }
    });
  },
  set: (data) => {
    return new Promise((resolve, reject) => {
      try {
        const result = EXT.storage.local.set(data);
        if (result && typeof result.then === 'function') {
          result.then(resolve).catch(reject);
        } else {
          EXT.storage.local.set(data, () => {
            if (EXT.runtime.lastError) {
              reject(new Error(EXT.runtime.lastError.message));
            } else {
              resolve();
            }
          });
        }
      } catch (error) {
        reject(error);
      }
    });
  },
  remove: (keys) => {
    return new Promise((resolve, reject) => {
      try {
        const result = EXT.storage.local.remove(keys);
        if (result && typeof result.then === 'function') {
          result.then(resolve).catch(reject);
        } else {
          EXT.storage.local.remove(keys, () => {
            if (EXT.runtime.lastError) {
              reject(new Error(EXT.runtime.lastError.message));
            } else {
              resolve();
            }
          });
        }
      } catch (error) {
        reject(error);
      }
    });
  }
};

// ===== CROSS-BROWSER MESSAGING =====
function sendMessage(message) {
  return new Promise((resolve, reject) => {
    try {
      const result = EXT.runtime.sendMessage(message);
      if (result && typeof result.then === 'function') {
        result.then(resolve).catch(reject);
      } else {
        EXT.runtime.sendMessage(message, (response) => {
          if (EXT.runtime.lastError) {
            reject(new Error(EXT.runtime.lastError.message));
          } else {
            resolve(response);
          }
        });
      }
    } catch (error) {
      reject(error);
    }
  });
}

// ===== TOTP IMPLEMENTATION =====
class TOTP {
  constructor(secret, digits = 6, period = 30) {
    this.secret = secret;
    this.digits = digits;
    this.period = period;
  }

  async generate(timestamp = null) {
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

    const signature = await crypto.subtle.sign(
      'HMAC',
      key,
      counterBytes
    );

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

// ===== ENCRYPTION HELPERS =====
async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptData(data, password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const key = await deriveKey(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoder.encode(JSON.stringify(data))
  );

  const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  result.set(salt, 0);
  result.set(iv, salt.length);
  result.set(new Uint8Array(encrypted), salt.length + iv.length);

  return result;
}

async function decryptData(encryptedData, password) {
  const data = new Uint8Array(encryptedData);
  const salt = data.slice(0, 16);
  const iv = data.slice(16, 28);
  const encrypted = data.slice(28);

  const key = await deriveKey(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encrypted
  );

  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(decrypted));
}

// ===== ACCOUNT MANAGEMENT =====
async function saveAccounts(accounts, password) {
  if (!password) {
    console.error('❌ No password provided');
    return false;
  }
  try {
    const encrypted = await encryptData(accounts, password);
    await storage.set({ [STORAGE_KEYS.ACCOUNTS]: Array.from(encrypted) });
    console.log('💾 Accounts saved successfully');
    return true;
  } catch (error) {
    console.error('Failed to save accounts:', error);
    return false;
  }
}

async function loadAccounts(password) {
  if (!password) {
    console.error('❌ No password provided');
    return null;
  }
  try {
    const result = await storage.get([STORAGE_KEYS.ACCOUNTS]);
    const encrypted = result[STORAGE_KEYS.ACCOUNTS];
    if (!encrypted) {
      console.log('📭 No accounts found in storage');
      return {};
    }
    const data = new Uint8Array(encrypted);
    const decrypted = await decryptData(data, password);
    console.log('📊 Accounts loaded successfully');
    return decrypted;
  } catch (error) {
    console.error('Failed to load accounts:', error);
    return null;
  }
}

// ===== RECOVERY MANAGEMENT =====
async function saveRecovery(recoveryData) {
  await storage.set({ [STORAGE_KEYS.RECOVERY]: recoveryData });
}

async function loadRecovery() {
  const result = await storage.get([STORAGE_KEYS.RECOVERY]);
  return result[STORAGE_KEYS.RECOVERY] || {};
}

async function saveCurrentState() {
  try {
    await storage.set({
      [STORAGE_KEYS.LAST_STATE]: {
        locked: currentState.locked,
        timestamp: Date.now()
      }
    });
  } catch (error) {
    console.error('Failed to save state:', error);
  }
}

// ===== SESSION MANAGEMENT =====
async function saveSessionData() {
  try {
    await storage.set({
      [STORAGE_KEYS.SESSION_EXPIRES_AT]: currentState.sessionExpiresAt
    });
  } catch (error) {
    console.error('Failed to save session:', error);
  }
}

async function loadSessionData() {
  try {
    const result = await storage.get([STORAGE_KEYS.SESSION_EXPIRES_AT]);
    return result[STORAGE_KEYS.SESSION_EXPIRES_AT] || null;
  } catch (error) {
    console.error('Failed to load session:', error);
    return null;
  }
}

// ===== LOAD TIMEOUT CONFIGURATION =====
async function loadTimeoutConfig() {
  const result = await storage.get([
    STORAGE_KEYS.TIMEOUT_TOTAL_SECONDS,
    STORAGE_KEYS.TIMEOUT_SECONDS,
    STORAGE_KEYS.TIMEOUT_MINUTES
  ]);

  let timeout = result[STORAGE_KEYS.TIMEOUT_TOTAL_SECONDS];

  // Backward compatibility with older installations
  if (timeout === undefined) {
    const minutes = Number(result[STORAGE_KEYS.TIMEOUT_MINUTES] ?? 1);
    const seconds = Number(result[STORAGE_KEYS.TIMEOUT_SECONDS] ?? 0);
    timeout = (minutes * 60) + seconds;
  }

  timeout = Number(timeout);

  if (!Number.isFinite(timeout) || timeout < 30) {
    timeout = 300;
  }

  AUTO_LOCK_CONFIG.timeoutSeconds = timeout;
  console.log('⏰ Loaded timeout config:', timeout, 'seconds');
  return timeout;
}

// ===== LOAD AUTO-LOCK ENABLED SETTING =====
async function loadAutoLockSetting() {
  try {
    const result = await storage.get([STORAGE_KEYS.AUTO_LOCK_ENABLED]);
    const enabled = result[STORAGE_KEYS.AUTO_LOCK_ENABLED];
    // Default to true if never set
    AUTO_LOCK_CONFIG.enabled = enabled !== undefined ? enabled : true;
    console.log('⏰ Auto-lock enabled:', AUTO_LOCK_CONFIG.enabled);
    return AUTO_LOCK_CONFIG.enabled;
  } catch (error) {
    console.error('Failed to load auto-lock setting:', error);
    AUTO_LOCK_CONFIG.enabled = true;
    return true;
  }
}

// ===== BACKGROUND TIMER =====
let backgroundTimer = null;

function startBackgroundTimer() {
  if (backgroundTimer) {
    clearInterval(backgroundTimer);
    backgroundTimer = null;
  }

  if (currentState.locked) {
    console.log('⏸️ Extension locked - not starting timer');
    return;
  }

  // Skip timer if auto-lock is disabled
  if (!AUTO_LOCK_CONFIG.enabled) {
    console.log('⏸️ Auto-lock disabled - not starting timer');
    return;
  }

  console.log('⏰ Starting background timer');

  backgroundTimer = setInterval(async () => {
    if (!currentState.locked && !currentState.isAutoLocking) {
      if (currentState.sessionExpiresAt) {
        const remaining = Math.max(0, Math.ceil((currentState.sessionExpiresAt - Date.now()) / 1000));

        if (remaining <= 0 && !currentState.isAutoLocking) {
          console.log('⏰ Session expired - auto-locking');
          currentState.isAutoLocking = true;

          if (backgroundTimer) {
            clearInterval(backgroundTimer);
            backgroundTimer = null;
          }

          currentState.locked = true;
          currentState.accounts = {};
          currentState.sessionExpiresAt = null;

          await storage.set({ [STORAGE_KEYS.LOCKED]: true });
          await storage.remove(STORAGE_KEYS.SESSION_EXPIRES_AT);
          try {
            await EXT.storage.session.remove([STORAGE_KEYS.SESSION_PASSWORD]);
          } catch (e) { }
          await saveCurrentState();

          try {
            await sendMessage({ type: 'AUTO_LOCKED' });
          } catch (e) { }

          setTimeout(() => {
            currentState.isAutoLocking = false;
          }, 2000);
        }
      }
    }
  }, 1000);
}

function stopBackgroundTimer() {
  if (backgroundTimer) {
    clearInterval(backgroundTimer);
    backgroundTimer = null;
    console.log('🛑 Background timer stopped');
  }
}

function getRemainingTime() {
  if (!currentState.sessionExpiresAt) return 0;
  return Math.max(0, Math.ceil((currentState.sessionExpiresAt - Date.now()) / 1000));
}

// ===== MESSAGE HANDLING =====
EXT.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('📨 Background received message:', message.type);

  (async () => {
    try {
      const response = await handleMessage(message, sender);
      console.log('📤 Background sending response:', response);
      sendResponse(response);
    } catch (error) {
      console.error('❌ Background error:', error);
      sendResponse({ success: false, error: error.message });
    }
  })();
  return true;
});

async function handleMessage(message, sender) {
  console.log('🔧 Handling message:', message.type);

  switch (message.type) {
    case 'INIT':
      return await handleInit();
    case 'GET_SESSION':
      return await handleGetSession();
    case 'SETUP_PASSWORD':
      return await handleSetupPassword(message.payload);
    case 'SETUP_RECOVERY':
      return await handleSetupRecovery(message.payload);
    case 'UNLOCK':
      return await handleUnlock(message.payload);
    case 'LOCK':
      return await handleLock();
    case 'GET_ACCOUNTS':
      return await handleGetAccounts();
    case 'ADD_ACCOUNT':
      return await handleAddAccount(message.payload);
    case 'DELETE_ACCOUNT':
      return await handleDeleteAccount(message.payload);
    case 'GENERATE_CODE':
      return await handleGenerateCode(message.payload);
    case 'FORGOT_PASSWORD':
      return await handleForgotPassword(message.payload);
    case 'RESET_PASSWORD':
      return await handleResetPassword(message.payload);
    case 'COPY_CODE':
      return await handleCopyCode(message.payload);
    case 'RESTORE_BACKUP':
      return await handleRestoreBackup(message.payload);
    case 'RESET_SESSION_TIMER':
      return await handleResetSessionTimer();
    case 'UPDATE_TIMEOUT':
      return await handleUpdateTimeout(message.payload);
    case 'SAVE_TIMEOUT':
      return await handleSaveTimeout(message.payload);
    case 'GET_DESCRIPTIONS':
      return await handleGetDescriptions();
    case 'RENAME_ACCOUNT':
      return await handleRenameAccount(message.payload);
    case 'UPDATE_ACCOUNT':
      return await handleUpdateAccount(message.payload);
    case 'REORDER_ACCOUNTS':
      return await handleReorderAccounts(message.payload);
    case 'TOGGLE_AUTO_LOCK':
      return await handleToggleAutoLock(message.payload);
    default:
      console.error('❌ Unknown message type:', message.type);
      throw new Error(`Unknown message type: ${message.type}`);
  }
}

// ===== HANDLERS =====
async function handleInit() {
  console.log('🔐 Initializing...');

  await loadTimeoutConfig();
  await loadAutoLockSetting();

  const result = await storage.get([
    STORAGE_KEYS.IS_SETUP,
    STORAGE_KEYS.LOCKED
  ]);

  const isSetup = result[STORAGE_KEYS.IS_SETUP];
  const locked = result[STORAGE_KEYS.LOCKED];

  const recovery = await loadRecovery();
  currentState.recovery = recovery;

  if (!isSetup) {
    return {
      success: true,
      state: 'setup',
      locked: true,
      autoLockEnabled: AUTO_LOCK_CONFIG.enabled
    };
  }

  // ⭐ TRY TO RESTORE PASSWORD FROM SESSION STORAGE
  // (session storage is cleared when browser closes)
  let passwordRestored = false;
  if (!currentState.password) {
    try {
      const sessionData = await EXT.storage.session.get([STORAGE_KEYS.SESSION_PASSWORD]);
      if (sessionData && sessionData[STORAGE_KEYS.SESSION_PASSWORD]) {
        currentState.password = sessionData[STORAGE_KEYS.SESSION_PASSWORD];
        passwordRestored = true;
        console.log('🔑 Password restored from session storage');
      } else {
        console.log('⚠️ No password in session storage (browser was closed)');
      }
    } catch (e) {
      console.warn('Could not check session storage:', e);
    }
  } else {
    passwordRestored = true;
  }

  // ⭐ CRITICAL FIX: If browser was closed and password is gone,
  // we MUST force lock — otherwise we show an unlocked but empty account list
  if (!passwordRestored) {
    console.log('🔒 Forcing lock: password not available (browser restart)');

    currentState.locked = true;
    currentState.password = null;
    currentState.accounts = {};
    currentState.sessionExpiresAt = null;

    await storage.set({ [STORAGE_KEYS.LOCKED]: true });
    await storage.remove(STORAGE_KEYS.SESSION_EXPIRES_AT);
    await saveCurrentState();

    return {
      success: true,
      state: 'locked',
      locked: true,
      accountCount: 0,
      sessionRemaining: 0,
      timeoutSeconds: AUTO_LOCK_CONFIG.timeoutSeconds,
      autoLockEnabled: AUTO_LOCK_CONFIG.enabled
    };
  }

  // ⭐ Check if session expired during offline time
  currentState.sessionExpiresAt = await loadSessionData();

  if (currentState.sessionExpiresAt && AUTO_LOCK_CONFIG.enabled) {
    const remaining = getRemainingTime();
    if (remaining <= 0 && locked !== true) {
      console.log('⏰ Session expired during init');
      currentState.locked = true;
      currentState.accounts = {};
      currentState.sessionExpiresAt = null;
      currentState.password = null;

      await storage.set({ [STORAGE_KEYS.LOCKED]: true });
      await storage.remove(STORAGE_KEYS.SESSION_EXPIRES_AT);
      try {
        await EXT.storage.session.remove([STORAGE_KEYS.SESSION_PASSWORD]);
      } catch (e) { }
      await saveCurrentState();

      return {
        success: true,
        state: 'locked',
        locked: true,
        accountCount: 0,
        sessionRemaining: 0,
        timeoutSeconds: AUTO_LOCK_CONFIG.timeoutSeconds,
        autoLockEnabled: AUTO_LOCK_CONFIG.enabled
      };
    }
  }

  currentState.locked = locked !== undefined ? locked : true;

  if (!currentState.locked && currentState.password) {
    const accounts = await loadAccounts(currentState.password);
    if (accounts !== null) {
      currentState.accounts = accounts;
      console.log('📊 Restored accounts on init:', Object.keys(accounts).length);
    } else {
      console.warn('⚠️ Could not restore accounts — forcing lock');
      currentState.locked = true;
      currentState.accounts = {};
      currentState.password = null;
      await storage.set({ [STORAGE_KEYS.LOCKED]: true });
      try {
        await EXT.storage.session.remove([STORAGE_KEYS.SESSION_PASSWORD]);
      } catch (e) { }
    }
  }

  if (!currentState.locked) {
    startBackgroundTimer();
  }

  return {
    success: true,
    state: currentState.locked ? 'locked' : 'unlocked',
    locked: currentState.locked,
    accountCount: Object.keys(currentState.accounts).length,
    sessionRemaining: getRemainingTime(),
    timeoutSeconds: AUTO_LOCK_CONFIG.timeoutSeconds,
    autoLockEnabled: AUTO_LOCK_CONFIG.enabled
  };
}

async function handleGetSession() {
  if (!currentState.sessionExpiresAt) {
    currentState.sessionExpiresAt = await loadSessionData();
  }

  const result = await storage.get([STORAGE_KEYS.LOCKED]);
  if (result[STORAGE_KEYS.LOCKED] !== undefined) {
    currentState.locked = result[STORAGE_KEYS.LOCKED];
  }

  return {
    success: true,
    sessionRemaining: AUTO_LOCK_CONFIG.enabled ? getRemainingTime() : 0,
    locked: currentState.locked,
    autoLockEnabled: AUTO_LOCK_CONFIG.enabled
  };
}

async function handleSetupPassword(payload) {
  const { password } = payload;

  if (!password || password.length < 6) {
    throw new Error('Password must be at least 6 characters');
  }

  currentState.password = password;
  await storage.set({ [STORAGE_KEYS.PASSWORD]: password });

  return { success: true };
}

async function handleSetupRecovery(payload) {
  const { answers } = payload;

  if (!answers || answers.length !== 3 || answers.some(a => !a || a.trim() === '')) {
    throw new Error('All 3 answers are required');
  }

  const recoveryData = {
    q1: answers[0].toLowerCase().trim(),
    q2: answers[1].toLowerCase().trim(),
    q3: answers[2].toLowerCase().trim()
  };

  currentState.recovery = recoveryData;
  await saveRecovery(recoveryData);
  await storage.set({ [STORAGE_KEYS.IS_SETUP]: true });

  const encrypted = await encryptData({}, currentState.password);
  await storage.set({ [STORAGE_KEYS.ACCOUNTS]: Array.from(encrypted) });
  await storage.set({ [STORAGE_KEYS.LOCKED]: false });

  await loadTimeoutConfig();

  currentState.locked = false;
  currentState.accounts = {};
  currentState.sessionExpiresAt = Date.now() + AUTO_LOCK_CONFIG.timeoutSeconds * 1000;

  // Save password to session storage
  try {
    await EXT.storage.session.set({ [STORAGE_KEYS.SESSION_PASSWORD]: currentState.password });
  } catch (e) { }

  await storage.set({ [STORAGE_KEYS.SESSION_EXPIRES_AT]: currentState.sessionExpiresAt });
  await saveCurrentState();
  startBackgroundTimer();

  return {
    success: true,
    sessionRemaining: getRemainingTime()
  };
}

async function handleUnlock(payload) {
  const { password } = payload;

  if (!password) {
    throw new Error('Password required');
  }

  const result = await storage.get([STORAGE_KEYS.PASSWORD]);
  const storedPassword = result[STORAGE_KEYS.PASSWORD];

  if (password !== storedPassword) {
    throw new Error('Wrong password');
  }

  await loadTimeoutConfig();
  await loadAutoLockSetting();

  const accounts = await loadAccounts(password);
  if (accounts === null) {
    throw new Error('Failed to decrypt accounts');
  }

  currentState.password = password;
  currentState.accounts = accounts;
  currentState.locked = false;
  currentState.isAutoLocking = false;

  // Set session expiration only if auto-lock is enabled
  if (AUTO_LOCK_CONFIG.enabled) {
    currentState.sessionExpiresAt = Date.now() + AUTO_LOCK_CONFIG.timeoutSeconds * 1000;
  } else {
    currentState.sessionExpiresAt = null;
  }

  // Save password to session storage
  try {
    await EXT.storage.session.set({ [STORAGE_KEYS.SESSION_PASSWORD]: password });
  } catch (e) {
    console.warn('Could not save to session storage:', e);
  }

  await storage.set({ [STORAGE_KEYS.LOCKED]: false });

  if (currentState.sessionExpiresAt) {
    await storage.set({ [STORAGE_KEYS.SESSION_EXPIRES_AT]: currentState.sessionExpiresAt });
  }

  await saveCurrentState();
  startBackgroundTimer();

  return {
    success: true,
    accounts: accounts,
    count: Object.keys(accounts).length,
    sessionRemaining: getRemainingTime(),
    timeoutSeconds: AUTO_LOCK_CONFIG.timeoutSeconds,
    autoLockEnabled: AUTO_LOCK_CONFIG.enabled
  };
}

async function handleLock() {
  currentState.locked = true;
  currentState.password = null;
  currentState.accounts = {};
  currentState.sessionExpiresAt = null;

  stopBackgroundTimer();
  await storage.set({ [STORAGE_KEYS.LOCKED]: true });
  await storage.remove(STORAGE_KEYS.SESSION_EXPIRES_AT);

  // Clear session password too
  try {
    await EXT.storage.session.remove([STORAGE_KEYS.SESSION_PASSWORD]);
  } catch (e) { }

  await saveCurrentState();
  return { success: true };
}

async function handleGetAccounts() {
  if (currentState.locked) {
    throw new Error('Extension is locked');
  }

  return {
    success: true,
    accounts: currentState.accounts,
    count: Object.keys(currentState.accounts).length
  };
}

async function handleAddAccount(payload) {
  if (currentState.locked) {
    throw new Error('Extension is locked');
  }

  const { name, secret } = payload;
  if (!name || !secret) {
    throw new Error('Name and secret are required');
  }

  currentState.accounts[name] = secret.toUpperCase();
  await saveAccounts(currentState.accounts, currentState.password);
  await saveCurrentState();

  return {
    success: true,
    accounts: currentState.accounts,
    count: Object.keys(currentState.accounts).length
  };
}

async function handleDeleteAccount(payload) {
  if (currentState.locked) {
    throw new Error('Extension is locked');
  }

  const { name } = payload;
  if (!name || !currentState.accounts[name]) {
    throw new Error('Account not found');
  }

  delete currentState.accounts[name];

  // Also remove description
  const result = await storage.get([STORAGE_KEYS.ACCOUNT_DESCRIPTIONS]);
  const descriptions = result[STORAGE_KEYS.ACCOUNT_DESCRIPTIONS] || {};
  delete descriptions[name];
  await storage.set({ [STORAGE_KEYS.ACCOUNT_DESCRIPTIONS]: descriptions });

  await saveAccounts(currentState.accounts, currentState.password);
  await saveCurrentState();

  return {
    success: true,
    accounts: currentState.accounts,
    count: Object.keys(currentState.accounts).length
  };
}

async function handleGenerateCode(payload) {
  const { name, secret } = payload;
  const secretKey = secret || currentState.accounts[name];

  if (!secretKey) {
    throw new Error('Secret not found');
  }

  const totp = new TOTP(secretKey);
  const code = await totp.generate();
  const remaining = totp.getRemaining();

  return {
    success: true,
    code: code,
    remaining: remaining
  };
}

async function handleForgotPassword(payload) {
  const { answers } = payload;

  if (!answers || answers.length !== 3) {
    throw new Error('All 3 answers are required');
  }

  const stored = currentState.recovery;
  const normalized = answers.map(a => a.toLowerCase().trim());

  if (normalized[0] !== stored.q1 ||
    normalized[1] !== stored.q2 ||
    normalized[2] !== stored.q3) {
    throw new Error('Answers do not match');
  }

  return { success: true };
}

async function handleResetPassword(payload) {
  const { newPassword } = payload;

  if (!newPassword || newPassword.length < 6) {
    throw new Error('Password must be at least 6 characters');
  }

  await saveAccounts(currentState.accounts, newPassword);
  currentState.password = newPassword;
  await storage.set({ [STORAGE_KEYS.PASSWORD]: newPassword });

  // Update session password too
  try {
    await EXT.storage.session.set({ [STORAGE_KEYS.SESSION_PASSWORD]: newPassword });
  } catch (e) { }

  await saveCurrentState();

  return { success: true };
}

async function handleCopyCode(payload) {
  const { code } = payload;
  try {
    await navigator.clipboard.writeText(code);
    return { success: true };
  } catch (error) {
    return { success: false, error: 'Clipboard not available' };
  }
}

async function handleRestoreBackup(payload) {
  console.log('📥 Background: Restoring backup...');

  if (currentState.locked) {
    throw new Error('Extension is locked. Please unlock first.');
  }

  const { accounts } = payload;

  if (!accounts || typeof accounts !== 'object') {
    throw new Error('Invalid accounts data');
  }

  for (const [name, secret] of Object.entries(accounts)) {
    if (typeof name !== 'string' || typeof secret !== 'string') {
      throw new Error(`Invalid account format for "${name}"`);
    }
    if (!name.trim() || !secret.trim()) {
      throw new Error(`Empty account name or secret for "${name}"`);
    }
  }

  currentState.accounts = accounts;

  const saved = await saveAccounts(currentState.accounts, currentState.password);
  if (!saved) {
    throw new Error('Failed to save accounts to storage');
  }

  await saveCurrentState();

  return {
    success: true,
    accounts: currentState.accounts,
    count: Object.keys(currentState.accounts).length
  };
}

async function handleResetSessionTimer() {
  console.log('🔄 Resetting session timer');

  if (!currentState.password) {
    try {
      const sessionData = await EXT.storage.session.get([STORAGE_KEYS.SESSION_PASSWORD]);
      if (sessionData && sessionData[STORAGE_KEYS.SESSION_PASSWORD]) {
        currentState.password = sessionData[STORAGE_KEYS.SESSION_PASSWORD];
      }
    } catch (e) { }
  }

  // Don't reset if auto-lock is disabled
  if (!AUTO_LOCK_CONFIG.enabled) {
    return {
      success: true,
      sessionRemaining: 0,
      disabled: true
    };
  }

  await loadTimeoutConfig();

  const timeout = AUTO_LOCK_CONFIG.timeoutSeconds;
  currentState.sessionExpiresAt = Date.now() + timeout * 1000;
  currentState.locked = false;

  await storage.set({
    [STORAGE_KEYS.SESSION_EXPIRES_AT]: currentState.sessionExpiresAt,
    [STORAGE_KEYS.LOCKED]: false
  });

  return {
    success: true,
    sessionRemaining: getRemainingTime()
  };
}

async function handleUpdateTimeout(payload) {
  console.log('⏰ Updating timeout setting:', payload);

  const minutes = Number(payload.minutes) || 0;
  const seconds = Number(payload.seconds) || 0;
  const totalSeconds = (minutes * 60) + seconds;

  if (!Number.isFinite(totalSeconds) || totalSeconds < 30) {
    throw new Error('Invalid timeout value. Must be at least 30 seconds.');
  }

  AUTO_LOCK_CONFIG.timeoutSeconds = totalSeconds;

  await storage.set({
    [STORAGE_KEYS.TIMEOUT_MINUTES]: minutes,
    [STORAGE_KEYS.TIMEOUT_SECONDS]: seconds,
    [STORAGE_KEYS.TIMEOUT_TOTAL_SECONDS]: totalSeconds
  });

  if (!currentState.locked && AUTO_LOCK_CONFIG.enabled) {
    currentState.sessionExpiresAt = Date.now() + totalSeconds * 1000;
    await storage.set({
      [STORAGE_KEYS.SESSION_EXPIRES_AT]: currentState.sessionExpiresAt
    });
  }

  return {
    success: true,
    sessionRemaining: getRemainingTime()
  };
}

async function handleSaveTimeout(payload) {
  console.log('💾 Saving timeout settings:', payload);

  const minutes = Number(payload.minutes) || 0;
  const seconds = Number(payload.seconds) || 0;
  const totalSeconds = (minutes * 60) + seconds;

  if (!Number.isFinite(totalSeconds) || totalSeconds < 30) {
    throw new Error('Invalid timeout value. Must be at least 30 seconds.');
  }

  AUTO_LOCK_CONFIG.timeoutSeconds = totalSeconds;

  await storage.set({
    [STORAGE_KEYS.TIMEOUT_MINUTES]: minutes,
    [STORAGE_KEYS.TIMEOUT_SECONDS]: seconds,
    [STORAGE_KEYS.TIMEOUT_TOTAL_SECONDS]: totalSeconds
  });

  console.log('✅ Timeout saved:', {
    minutes: minutes,
    seconds: seconds,
    totalSeconds: totalSeconds
  });

  // Restore password if missing
  if (!currentState.password) {
    try {
      const sessionData = await EXT.storage.session.get([STORAGE_KEYS.SESSION_PASSWORD]);
      if (sessionData && sessionData[STORAGE_KEYS.SESSION_PASSWORD]) {
        currentState.password = sessionData[STORAGE_KEYS.SESSION_PASSWORD];
      }
    } catch (e) { }
  }

  // Restore accounts if missing
  if (!currentState.locked && Object.keys(currentState.accounts).length === 0 && currentState.password) {
    const accounts = await loadAccounts(currentState.password);
    if (accounts) {
      currentState.accounts = accounts;
      console.log('📊 Restored accounts during save timeout:', Object.keys(accounts).length);
    }
  }

  // Reset session timer if unlocked AND auto-lock enabled
  if (!currentState.locked && AUTO_LOCK_CONFIG.enabled) {
    currentState.sessionExpiresAt = Date.now() + totalSeconds * 1000;
    await storage.set({
      [STORAGE_KEYS.SESSION_EXPIRES_AT]: currentState.sessionExpiresAt,
      [STORAGE_KEYS.LOCKED]: false
    });
  }

  // Verify the save
  const verify = await storage.get([
    STORAGE_KEYS.TIMEOUT_TOTAL_SECONDS,
    STORAGE_KEYS.TIMEOUT_MINUTES,
    STORAGE_KEYS.TIMEOUT_SECONDS
  ]);

  console.log('🔍 Verification - stored values:', verify);

  return {
    success: true,
    saved: {
      minutes: verify[STORAGE_KEYS.TIMEOUT_MINUTES],
      seconds: verify[STORAGE_KEYS.TIMEOUT_SECONDS],
      totalSeconds: verify[STORAGE_KEYS.TIMEOUT_TOTAL_SECONDS]
    },
    sessionRemaining: getRemainingTime()
  };
}

async function handleGetDescriptions() {
  const result = await storage.get([STORAGE_KEYS.ACCOUNT_DESCRIPTIONS]);
  return {
    success: true,
    descriptions: result[STORAGE_KEYS.ACCOUNT_DESCRIPTIONS] || {}
  };
}

async function handleRenameAccount(payload) {
  if (currentState.locked) {
    throw new Error('Extension is locked');
  }

  const { oldName, newName } = payload;

  if (!oldName || !newName) {
    throw new Error('Old name and new name are required');
  }

  if (!currentState.accounts[oldName]) {
    throw new Error('Account not found');
  }

  if (currentState.accounts[newName] !== undefined) {
    throw new Error('An account with that name already exists');
  }

  const secret = currentState.accounts[oldName];
  delete currentState.accounts[oldName];
  currentState.accounts[newName] = secret;

  // Also rename description
  const result = await storage.get([STORAGE_KEYS.ACCOUNT_DESCRIPTIONS]);
  const descriptions = result[STORAGE_KEYS.ACCOUNT_DESCRIPTIONS] || {};
  if (descriptions[oldName]) {
    descriptions[newName] = descriptions[oldName];
    delete descriptions[oldName];
    await storage.set({ [STORAGE_KEYS.ACCOUNT_DESCRIPTIONS]: descriptions });
  }

  await saveAccounts(currentState.accounts, currentState.password);
  await saveCurrentState();

  return {
    success: true,
    accounts: currentState.accounts,
    count: Object.keys(currentState.accounts).length,
    oldName: oldName,
    newName: newName
  };
}

async function handleUpdateAccount(payload) {
  if (currentState.locked) {
    throw new Error('Extension is locked');
  }

  const { name, newName, secret, description } = payload;

  if (!name) {
    throw new Error('Account name is required');
  }

  if (!currentState.accounts[name]) {
    throw new Error('Account not found');
  }

  // Get existing secret (or use new one if provided)
  let finalSecret = currentState.accounts[name];
  if (secret && secret.trim()) {
    finalSecret = secret.trim().toUpperCase();
    if (!/^[A-Z2-7]+$/.test(finalSecret.replace(/\s/g, ''))) {
      throw new Error('Invalid secret format (Base32)');
    }
  }

  // Handle rename if new name is provided and different
  let finalName = name;
  if (newName && newName.trim() && newName !== name) {
    if (currentState.accounts[newName] !== undefined) {
      throw new Error('An account with that name already exists');
    }
    finalName = newName.trim();
  }

  // Remove old entry
  delete currentState.accounts[name];

  // Add updated entry
  currentState.accounts[finalName] = finalSecret;

  // Store description separately
  if (description !== undefined) {
    const result = await storage.get([STORAGE_KEYS.ACCOUNT_DESCRIPTIONS]);
    const descriptions = result[STORAGE_KEYS.ACCOUNT_DESCRIPTIONS] || {};

    // Remove old description if renamed
    if (finalName !== name) {
      delete descriptions[name];
    }

    if (description.trim()) {
      descriptions[finalName] = description.trim();
    } else {
      delete descriptions[finalName];
    }

    await storage.set({ [STORAGE_KEYS.ACCOUNT_DESCRIPTIONS]: descriptions });
  }

  await saveAccounts(currentState.accounts, currentState.password);
  await saveCurrentState();

  return {
    success: true,
    accounts: currentState.accounts,
    count: Object.keys(currentState.accounts).length,
    oldName: name,
    newName: finalName
  };
}

async function handleReorderAccounts(payload) {
  if (currentState.locked) {
    throw new Error('Extension is locked');
  }

  const { orderedNames } = payload;

  if (!orderedNames || !Array.isArray(orderedNames)) {
    throw new Error('Invalid order data');
  }

  // Verify all accounts exist
  const currentNames = Object.keys(currentState.accounts);
  if (orderedNames.length !== currentNames.length) {
    throw new Error('Account count mismatch');
  }

  for (const name of orderedNames) {
    if (!currentState.accounts[name]) {
      throw new Error(`Account "${name}" not found`);
    }
  }

  // Rebuild accounts object in new order
  const reorderedAccounts = {};
  for (const name of orderedNames) {
    reorderedAccounts[name] = currentState.accounts[name];
  }

  currentState.accounts = reorderedAccounts;

  await saveAccounts(currentState.accounts, currentState.password);
  await saveCurrentState();

  console.log('📦 Reordered accounts:', orderedNames);

  return {
    success: true,
    accounts: currentState.accounts,
    count: Object.keys(currentState.accounts).length
  };
}

async function handleToggleAutoLock(payload) {
  console.log('🔧 Toggling auto-lock:', payload);

  const { enabled } = payload;

  if (typeof enabled !== 'boolean') {
    throw new Error('Invalid enabled value');
  }

  AUTO_LOCK_CONFIG.enabled = enabled;
  await storage.set({ [STORAGE_KEYS.AUTO_LOCK_ENABLED]: enabled });

  if (!currentState.locked) {
    if (enabled) {
      // Turning ON — start timer with current timeout
      await loadTimeoutConfig();
      currentState.sessionExpiresAt = Date.now() + AUTO_LOCK_CONFIG.timeoutSeconds * 1000;
      await storage.set({
        [STORAGE_KEYS.SESSION_EXPIRES_AT]: currentState.sessionExpiresAt
      });
      startBackgroundTimer();
    } else {
      // Turning OFF — stop timer, clear session expiration
      stopBackgroundTimer();
      currentState.sessionExpiresAt = null;
      await storage.remove(STORAGE_KEYS.SESSION_EXPIRES_AT);
    }
  }

  console.log(`✅ Auto-lock ${enabled ? 'enabled' : 'disabled'}`);

  return {
    success: true,
    enabled: enabled,
    sessionRemaining: getRemainingTime()
  };
}

// ===== STORAGE CHANGE LISTENER =====
EXT.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'local') {
    console.log('🔄 Storage changed:', Object.keys(changes));

    if (changes[STORAGE_KEYS.TIMEOUT_TOTAL_SECONDS]) {
      console.log('⏰ Timeout changed:', {
        old: changes[STORAGE_KEYS.TIMEOUT_TOTAL_SECONDS].oldValue,
        new: changes[STORAGE_KEYS.TIMEOUT_TOTAL_SECONDS].newValue
      });

      if (changes[STORAGE_KEYS.TIMEOUT_TOTAL_SECONDS].newValue) {
        AUTO_LOCK_CONFIG.timeoutSeconds = changes[STORAGE_KEYS.TIMEOUT_TOTAL_SECONDS].newValue;
      }
    }

    if (changes[STORAGE_KEYS.AUTO_LOCK_ENABLED]) {
      console.log('🔐 Auto-lock setting changed:', {
        old: changes[STORAGE_KEYS.AUTO_LOCK_ENABLED].oldValue,
        new: changes[STORAGE_KEYS.AUTO_LOCK_ENABLED].newValue
      });

      if (changes[STORAGE_KEYS.AUTO_LOCK_ENABLED].newValue !== undefined) {
        AUTO_LOCK_CONFIG.enabled = changes[STORAGE_KEYS.AUTO_LOCK_ENABLED].newValue;
      }
    }
  }
});

// ===== KEEP SERVICE WORKER ALIVE =====
let keepAliveInterval = null;

function startKeepAlive() {
  if (keepAliveInterval) {
    clearInterval(keepAliveInterval);
  }
  keepAliveInterval = setInterval(() => {
    console.log('💓 Keep alive ping');
  }, 20000);
}

function stopKeepAlive() {
  if (keepAliveInterval) {
    clearInterval(keepAliveInterval);
    keepAliveInterval = null;
  }
}

// ===== INITIALIZATION =====
console.log('🔐 Secure Authenticator background service worker loaded');

EXT.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    console.log('✅ Extension installed - ready for setup');
    await storage.set({ [STORAGE_KEYS.LOCKED]: true });
    await storage.set({ [STORAGE_KEYS.IS_SETUP]: false });
    await storage.set({
      [STORAGE_KEYS.TIMEOUT_MINUTES]: 1,
      [STORAGE_KEYS.TIMEOUT_SECONDS]: 0,
      [STORAGE_KEYS.TIMEOUT_TOTAL_SECONDS]: 60,
      [STORAGE_KEYS.AUTO_LOCK_ENABLED]: true
    });
  }
});

EXT.runtime.onStartup.addListener(async () => {
  console.log('🚀 Extension starting up...');
  const result = await storage.get([STORAGE_KEYS.LOCKED]);
  const locked = result[STORAGE_KEYS.LOCKED];

  await loadTimeoutConfig();
  await loadAutoLockSetting();

  if (locked !== false) {
    currentState.locked = true;
    currentState.password = null;
    currentState.accounts = {};
    stopBackgroundTimer();
  } else {
    currentState.sessionExpiresAt = await loadSessionData();
    startBackgroundTimer();
  }

  startKeepAlive();
});

startKeepAlive();

console.log('✅ Background service worker ready');
console.log('⏰ Auto-lock timeout:', AUTO_LOCK_CONFIG.timeoutSeconds, 'seconds');
console.log('🔐 Auto-lock enabled:', AUTO_LOCK_CONFIG.enabled);