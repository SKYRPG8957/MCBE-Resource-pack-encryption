
// ... (Previous content of script.js is preserved, we are appending/replacing logically)
// Since replace failed, I will use append via a smart replace of the end of file.

// Existing startDecryptProcess was incomplete in the view. I need to be careful.
// I will rewrite the entire startDecryptProcess and startHackSimulation to be safe.

async function startDecryptProcess() {
    const t = i18n[currentLang];
    try {
        const keyStr = dom.decryptKeyInput.value.trim();
        if (keyStr.length !== 32) {
            showStatus(t.error_key_length, 'error');
            return;
        }
        const masterKey = keyStr;

        dom.submitBtn.disabled = true;
        dom.btnText.textContent = t.btn_processing;
        showStatus(t.status_decrypt, 'success');
        updateProgress(10, t.status_decrypt);

        let loadedZip;
        if (currentMode === 'zip') {
            const zip = new JSZip();
            loadedZip = await zip.loadAsync(currentFiles);
        } else {
            loadedZip = new JSZip();
            // For folder decrypt, we must treat it as a zip struct
            if (currentFiles[0] && currentFiles[0].webkitRelativePath) {
                for (const file of currentFiles) {
                    const parts = file.webkitRelativePath.split('/');
                    const relativePath = parts.slice(1).join('/');
                    if (relativePath) loadedZip.file(relativePath, file);
                }
            }
        }

        const outZip = new JSZip();
        const files = [];
        loadedZip.forEach((path, file) => { if (!file.dir) files.push(path); });

        // VERIFICATION: Check if key is correct by parsing contents.json
        let validationSuccess = false;
        const contentsFiles = files.filter(n => n.endsWith('contents.json'));
        const fileKeyMap = {};

        const parseContentJson = async (path) => {
            const data = await loadedZip.file(path).async('uint8array');
            const headerSize = 256;
            if (data.length <= headerSize) return;

            const encryptedBody = data.slice(headerSize);
            const decryptedBody = decryptBytes(encryptedBody, masterKey);
            const decDecoder = new TextDecoder('utf-8');
            try {
                const jsonStr = decDecoder.decode(decryptedBody);
                const content = JSON.parse(jsonStr);
                if (content.content) {
                    content.content.forEach(c => {
                        fileKeyMap[c.path] = c.key;
                    });
                    validationSuccess = true;
                }
            } catch (e) {
                // Parsing failed, meaning key is likely wrong
            }
        };

        for (const cPath of contentsFiles) {
            await parseContentJson(cPath);
        }

        // If we found contents.json but failed to parse ANY of them, key is wrong.
        if (contentsFiles.length > 0 && !validationSuccess) {
            throw new Error("Incorrect Key! Decryption failed.");
        }

        // Decrypt Files
        let count = 0;
        for (const name of files) {
            if (name.endsWith('contents.json')) continue;
            const data = await loadedZip.file(name).async('uint8array');

            if (fileKeyMap[name]) {
                const key = fileKeyMap[name];
                const decrypted = decryptBytes(data, key);
                outZip.file(name, decrypted);
            } else {
                // Not in map? Copy as is (or maybe it uses master key if legacy?)
                // Current spec says resources have individual keys.
                outZip.file(name, data);
            }
            count++;
            if (count % 10 === 0) updateProgress(10 + (count / files.length) * 80, t.status_decrypt);
        }

        updateProgress(90, t.status_compress);
        const blob = await outZip.generateAsync({ type: "blob" });
        saveAs(blob, `decrypted_pack.zip`);

        showStatus(t.status_done, 'success');
        updateProgress(100, t.status_done);
        dom.submitBtn.disabled = false;
        updateButtonLabel();

    } catch (e) {
        console.error(e);
        const msg = e.message === "Incorrect Key! Decryption failed." ? e.message : 'Decryption Error: ' + e.message;
        showStatus(msg, 'error');
        dom.btnText.textContent = t.btn_retry;
        dom.submitBtn.disabled = false;
    }
}

// --- Hack Simulation ---
async function startHackSimulation() {
    const terminal = document.getElementById('hackTerminal');
    const output = document.getElementById('hackOutput');
    const btn = document.getElementById('btnHack');

    // Safety check just in case
    if (!terminal || !output || !btn) return;

    terminal.style.display = 'block';
    btn.disabled = true;
    btn.textContent = "ATTACKING...";

    let logs = [];
    const maxLogs = 10;
    const context = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    const addLog = (msg) => {
        logs.push(msg);
        if (logs.length > maxLogs) logs.shift();
        output.innerHTML = logs.join('<br>');
    };

    addLog("Injecting payload...");
    await new Promise(r => setTimeout(r, 800));
    addLog("Bypassing security gate...");
    await new Promise(r => setTimeout(r, 600));
    addLog("Starting brute-force engine (Threads: 256)...");
    await new Promise(r => setTimeout(r, 800));

    let attempts = 0;
    setInterval(() => {
        attempts += Math.floor(Math.random() * 500) + 100;
        const randKey = Array(32).fill(0).map(() => context.charAt(Math.floor(Math.random() * context.length))).join('');
        addLog(`[FAIL] ${randKey} (0.00ms)`);

        const hint = document.getElementById('decryptKeyHint');
        if (hint) {
            hint.textContent = `Attempts: ${attempts.toLocaleString()}`;
            hint.style.color = '#ef4444';
        }
    }, 50);
}
