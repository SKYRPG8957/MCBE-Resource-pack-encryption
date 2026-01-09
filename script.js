
// --- Constants ---
const KEY_LENGTH = 32;
const VERSION = new Uint8Array([0, 0, 0, 0]);
const MAGIC = new Uint8Array([0xFC, 0xB9, 0xCF, 0x9B]);

// --- DOM Elements ---
const dom = {
    container: document.getElementById('appContainer'),
    dropZone: document.getElementById('dropZone'),
    zipInput: document.getElementById('zipInput'),
    folderInput: document.getElementById('folderInput'),
    uploadPlaceholder: document.getElementById('uploadPlaceholder'),
    fileInfoDisplay: document.getElementById('fileInfoDisplay'),
    filenameText: document.getElementById('filenameText'),
    submitBtn: document.getElementById('submitBtn'),
    form: document.getElementById('uploadForm'),
    statusMessage: document.getElementById('statusMessage'),
    btnText: document.getElementById('btnText'),
    progressContainer: document.getElementById('progressContainer'),
    progressBar: document.getElementById('progressBar'),
    progressText: document.getElementById('progressText'),
    tabs: document.querySelectorAll('.tab'),
    // Icons
    iconZip: document.getElementById('iconZip'),
    iconFolder: document.getElementById('iconFolder'),
    // Key Controls
    keyModeRadios: document.getElementsByName('keyMode'),
    manualKeyContainer: document.getElementById('manualKeyContainer'),
    manualKeyInput: document.getElementById('manualKeyInput'),
    keyLengthHint: document.getElementById('keyLengthHint'),
    // Tree Controls
    fileTreeContainer: document.getElementById('fileTreeContainer'),
    btnExpandAll: document.getElementById('btnExpandAll'),
    btnCollapseAll: document.getElementById('btnCollapseAll'),
    btnResetTree: document.getElementById('btnResetTree')
};

// --- State ---
let currentFiles = null;
let currentMode = 'zip';
let currentLang = 'en';
let cachedZip = null; // Cache loaded JSZip object for tree operations
let fileTreeData = {}; // Store exclusion state: path -> boolean (encrypted?)

// --- Translations ---
const i18n = {
    en: {
        title: "Pack Encryptor",
        subtitle: "Secure specific assets while keeping manifests readable.",
        tab_zip: "ZIP File",
        tab_folder: "Folder",
        drop_text: "Drop %s here",
        drop_txt_zip: "ZIP file",
        drop_txt_folder: "Folder",
        drop_hint: "or click to browse",
        change_file: "Click to change",
        options_title: "Encryption Options",
        opt_manifest: "Exclude manifest.json",
        opt_icon: "Exclude pack_icon.png",
        opt_bug_icon: "Exclude bug_pack_icon.png",
        key_title: "Key Management",
        key_auto: "Auto Generate",
        key_manual: "Manual Input",
        key_placeholder: "Enter 32-character key",

        tree_title: "Select Files to Encrypt",
        tree_hint: "Uncheck files to exclude them from encryption.",
        tree_placeholder: "Upload a file or folder to view structure",
        btn_expand: "Expand All",
        btn_collapse: "Collapse All",
        btn_reset: "Reset",

        btn_start: "Encrypt & Download",
        btn_processing: "Processing...",
        btn_retry: "Retry",
        status_read_zip: "Reading ZIP file...",
        status_read_folder: "Reading Folder...",
        status_encrypt: "Encrypting files...",
        status_compress: "Compressing...",
        status_done: "Done!",
        status_success: "Success! Download started.",
        error_file_type: "Please drop a valid .zip file.",
        error_folder_type: "Please drop a folder.",
        error_key_length: "Key must be exactly 32 characters."
    },
    ko: {
        title: "리소스팩 암호화",
        subtitle: "매니페스트는 유지하고 리소스만 안전하게 보호하세요.",
        tab_zip: "ZIP 파일",
        tab_folder: "폴더",
        drop_text: "%s을(를) 여기에 놓으세요",
        drop_txt_zip: "ZIP 파일",
        drop_txt_folder: "폴더",
        drop_hint: "또는 클릭하여 찾기",
        change_file: "클릭해서 변경",
        options_title: "암호화 옵션",
        opt_manifest: "manifest.json 제외",
        opt_icon: "pack_icon.png 제외",
        opt_bug_icon: "bug_pack_icon.png 제외",
        key_title: "키 관리",
        key_auto: "자동 생성",
        key_manual: "직접 입력",
        key_placeholder: "32자리 키 입력",

        tree_title: "암호화할 파일 선택",
        tree_hint: "암호화하지 않을 파일은 체크를 해제하세요.",
        tree_placeholder: "파일이나 폴더를 업로드하면 구조가 표시됩니다.",
        btn_expand: "모두 펼치기",
        btn_collapse: "모두 접기",
        btn_reset: "초기화",

        btn_start: "암호화 및 다운로드",
        btn_processing: "처리 중...",
        btn_retry: "다시 시도",
        status_read_zip: "ZIP 읽는 중...",
        status_read_folder: "폴더 읽는 중...",
        status_encrypt: "암호화 진행 중...",
        status_compress: "압축하는 중...",
        status_done: "완료!",
        status_success: "완료되었습니다! 다운로드 시작.",
        error_file_type: "올바른 .zip 파일을 넣어주세요.",
        error_folder_type: "폴더를 넣어주세요.",
        error_key_length: "키는 정확히 32자리여야 합니다."
    },
    ja: {
        title: "パック暗号化ツール",
        subtitle: "マニフェストを維持したままリソースを保護します。",
        tab_zip: "ZIPファイル",
        tab_folder: "フォルダ",
        drop_text: "ここに%sをドロップ",
        drop_txt_zip: "ZIPファイル",
        drop_txt_folder: "フォルダ",
        drop_hint: "またはクリックして参照",
        change_file: "クリックして変更",
        options_title: "暗号化オプション",
        opt_manifest: "manifest.json を除外",
        opt_icon: "pack_icon.png を除外",
        opt_bug_icon: "bug_pack_icon.png を除外",
        key_title: "キー管理",
        key_auto: "自動生成",
        key_manual: "手動入力",
        key_placeholder: "32文字のキーを入力",

        tree_title: "暗号化するファイルを選択",
        tree_hint: "暗号化したくないファイルのチェックを外してください。",
        tree_placeholder: "ファイルまたはフォルダをアップロードして構造を表示",
        btn_expand: "すべて展開",
        btn_collapse: "すべて折りたたむ",
        btn_reset: "リセット",

        btn_start: "暗号化してダウンロード",
        btn_processing: "処理中...",
        btn_retry: "再試行",
        status_read_zip: "ZIPを読み込み中...",
        status_read_folder: "フォルダを読み込み中...",
        status_encrypt: "ファイルを暗号化中...",
        status_compress: "圧縮中...",
        status_done: "完了!",
        status_success: "暗号化が完了しました!",
        error_file_type: "有効な.zipファイルをドロップしてください。",
        error_folder_type: "フォルダをドロップしてください。",
        error_key_length: "キーは正確に32文字である必要があります。"
    },
    zh: {
        title: "资源包加密器",
        subtitle: "保护资源文件的同时保持清单文件可读。",
        tab_zip: "ZIP文件",
        tab_folder: "文件夹",
        drop_text: "将%s拖放到此处",
        drop_txt_zip: "ZIP文件",
        drop_txt_folder: "文件夹",
        drop_hint: "或点击浏览",
        change_file: "点击更改",
        options_title: "加密选项",
        opt_manifest: "排除 manifest.json",
        opt_icon: "排除 pack_icon.png",
        opt_bug_icon: "排除 bug_pack_icon.png",
        key_title: "密钥管理",
        key_auto: "自动生成",
        key_manual: "手动输入",
        key_placeholder: "输入32位密钥",

        tree_title: "选择要加密的文件",
        tree_hint: "取消选中以将其从加密中排除。",
        tree_placeholder: "上传文件或文件夹以查看结构",
        btn_expand: "全部展开",
        btn_collapse: "全部折叠",
        btn_reset: "重置",

        btn_start: "加密并下载",
        btn_processing: "处理中...",
        btn_retry: "重试",
        status_read_zip: "正在读取ZIP...",
        status_read_folder: "正在读取文件夹...",
        status_encrypt: "正在加密文件...",
        status_compress: "正在压缩...",
        status_done: "完成!",
        status_success: "加密完成！",
        error_file_type: "请拖入有效的.zip文件。",
        error_folder_type: "请拖入文件夹。",
        error_key_length: "密钥必须正好是32个字符。"
    },
    ru: {
        title: "Шифрование Пакетов",
        subtitle: "Защитите ресурсы, сохранив манифест читаемым.",
        tab_zip: "ZIP Архив",
        tab_folder: "Папка",
        drop_text: "Перетащите %s сюда",
        drop_txt_zip: "ZIP файл",
        drop_txt_folder: "папку",
        drop_hint: "или нажмите для выбора",
        change_file: "Нажмите, чтобы изменить",
        options_title: "Опции шифрования",
        opt_manifest: "Исключить manifest.json",
        opt_icon: "Исключить pack_icon.png",
        opt_bug_icon: "Исключить bug_pack_icon.png",
        key_title: "Управление ключом",
        key_auto: "Авто (генерировать)",
        key_manual: "Вручную",
        key_placeholder: "Введите 32-значный ключ",

        tree_title: "Выберите файлы для шифрования",
        tree_hint: "Снимите галочки с файлов, которые не нужно шифровать.",
        tree_placeholder: "Загрузите файл или папку, чтобы увидеть структуру",
        btn_expand: "Развернуть",
        btn_collapse: "Свернуть",
        btn_reset: "Сброс",

        btn_start: "Зашифровать и Скачать",
        btn_processing: "Обработка...",
        btn_retry: "Повторить",
        status_read_zip: "Чтение ZIP...",
        status_read_folder: "Чтение папки...",
        status_encrypt: "Шифрование файлов...",
        status_compress: "Сжатие...",
        status_done: "Готово!",
        status_success: "Успешно!",
        error_file_type: "Пожалуйста, выберите .zip файл.",
        error_folder_type: "Пожалуйста, выберите папку.",
        error_key_length: "Ключ должен содержать ровно 32 символа."
    }
};

// --- Initialization ---
function init() {
    // Detect Language
    const rawLang = navigator.language || navigator.userLanguage;
    const langCode = rawLang.split('-')[0]; // en-US -> en

    if (i18n[langCode]) setLanguage(langCode);
    else setLanguage('en');

    setupEventListeners();
    updateModeUI('zip');
}

function setLanguage(lang) {
    if (!i18n[lang]) return;
    currentLang = lang;

    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (i18n[lang][key]) {
            if (key === 'drop_text') {
                updateDropText();
            } else if (key.startsWith('opt_')) {
                el.innerHTML = i18n[lang][key]
                    .replace('manifest.json', '<strong>manifest.json</strong>')
                    .replace('pack_icon.png', '<strong>pack_icon.png</strong>')
                    .replace('bug_pack_icon.png', '<strong>bug_pack_icon.png</strong>');
            } else {
                el.textContent = i18n[lang][key];
            }
        }
    });

    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.dataset.i18nPlaceholder;
        if (i18n[lang][key]) el.placeholder = i18n[lang][key];
    });

    if (!dom.submitBtn.disabled) {
        dom.btnText.textContent = i18n[lang].btn_start;
    }
}

function updateModeUI(mode) {
    currentMode = mode;
    dom.container.setAttribute('data-mode', mode);

    dom.tabs.forEach(t => {
        if (t.dataset.mode === mode) t.classList.add('active');
        else t.classList.remove('active');
    });

    if (mode === 'zip') {
        dom.iconZip.style.display = 'block';
        dom.iconFolder.style.display = 'none';
    } else {
        dom.iconZip.style.display = 'none';
        dom.iconFolder.style.display = 'block';
    }

    updateDropText();
    resetFile();
}

function updateDropText() {
    const t = i18n[currentLang];
    const key = currentMode === 'zip' ? 'drop_txt_zip' : 'drop_txt_folder';
    const text = t.drop_text.replace('%s', t[key]);
    const dropTextEl = dom.dropZone.querySelector('.upload-text');
    if (dropTextEl) dropTextEl.textContent = text;
}

function setupEventListeners() {
    // Tabs
    dom.tabs.forEach(tab => {
        if (tab.classList.contains('tab-indicator')) return;
        tab.addEventListener('click', () => {
            updateModeUI(tab.dataset.mode);
        });
    });

    // Key Mode Switch
    Array.from(dom.keyModeRadios).forEach(rad => {
        rad.addEventListener('change', (e) => {
            if (e.target.value === 'manual') dom.manualKeyContainer.style.display = 'block';
            else dom.manualKeyContainer.style.display = 'none';
        });
    });

    // Key Validation
    dom.manualKeyInput.addEventListener('input', (e) => {
        const val = e.target.value;
        dom.keyLengthHint.textContent = `${val.length} / 32`;
        if (val.length === 32) dom.keyLengthHint.style.color = '#10b981';
        else dom.keyLengthHint.style.color = 'var(--text-muted)';
    });

    // Tree Controls
    dom.btnExpandAll.addEventListener('click', () => toggleTreeAll(true));
    dom.btnCollapseAll.addEventListener('click', () => toggleTreeAll(false));
    dom.btnResetTree.addEventListener('click', () => {
        if (currentFiles) loadFileTree(); // Reload to reset state
    });

    // Drag & Drop
    dom.dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dom.dropZone.classList.add('drag-over');
    });
    dom.dropZone.addEventListener('dragleave', () => {
        dom.dropZone.classList.remove('drag-over');
    });
    dom.dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dom.dropZone.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length > 0) handleFiles(files);
    });

    dom.dropZone.addEventListener('click', () => {
        if (currentMode === 'zip') dom.zipInput.click();
        else dom.folderInput.click();
    });

    dom.zipInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) handleFiles(e.target.files);
    });

    dom.folderInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) handleFiles(e.target.files);
    });

    dom.form.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!currentFiles) return;
        await startProcess();
    });
}

function handleFiles(fileList) {
    if (currentMode === 'zip') {
        const file = fileList[0];
        if (!file.name.toLowerCase().endsWith('.zip')) {
            showStatus(i18n[currentLang].error_file_type, 'error');
            return;
        }
        currentFiles = file;
        dom.filenameText.textContent = file.name;
    } else {
        if (fileList.length > 0) {
            currentFiles = fileList;
            let name = "Selected Folder";
            if (fileList[0].webkitRelativePath) {
                name = fileList[0].webkitRelativePath.split('/')[0];
            } else if (fileList.length === 1) {
                name = fileList[0].name;
            }
            dom.filenameText.textContent = `${name} (${fileList.length} files)`;
        }
    }

    dom.uploadPlaceholder.style.display = 'none';
    dom.fileInfoDisplay.style.display = 'flex';
    dom.submitBtn.disabled = false;
    dom.statusMessage.style.display = 'none';
    dom.progressContainer.style.display = 'none';

    // Trigger Tree Loading
    loadFileTree();
}

function resetFile() {
    currentFiles = null;
    cachedZip = null;
    dom.zipInput.value = '';
    dom.folderInput.value = '';
    dom.uploadPlaceholder.style.display = 'block';
    dom.fileInfoDisplay.style.display = 'none';
    dom.submitBtn.disabled = true;
    dom.statusMessage.style.display = 'none';
    dom.progressContainer.style.display = 'none';

    // Reset Tree
    dom.fileTreeContainer.innerHTML = `<div class="tree-placeholder" data-i18n="tree_placeholder">${i18n[currentLang].tree_placeholder}</div>`;
}

// --- Tree Logic ---

async function loadFileTree() {
    dom.fileTreeContainer.innerHTML = '<div style="padding:1rem; text-align:center;">Loading tree...</div>';

    const zip = new JSZip();
    let zipObj;

    if (currentMode === 'zip') {
        zipObj = await zip.loadAsync(currentFiles);
    } else {
        // Folder Mode: Construct a dummy zip structure to reuse parsing logic
        // Or manually parse webkitRelativePaths
        // Let's use JSZip to standardize access.
        zipObj = new JSZip();
        for (const file of currentFiles) {
            if (file.webkitRelativePath) {
                // Remove root folder from path to show internal structure
                // e.g. "MyPack/textures/..." -> "textures/..."
                const parts = file.webkitRelativePath.split('/');
                const relativePath = parts.slice(1).join('/');
                if (relativePath) zipObj.file(relativePath, "dummy"); // Content doesn't matter for tree
            }
        }
    }

    cachedZip = zipObj;

    // Build Hierarchy
    const root = { name: "Root", path: "", children: {}, type: 'folder', isRoot: true };

    zipObj.forEach((relativePath, file) => {
        // Filter out directories from JSZip (they end with /)
        if (file.dir) return; // We build folder structure from file paths

        const parts = relativePath.split('/');
        let current = root;

        parts.forEach((part, index) => {
            if (index === parts.length - 1) {
                // File
                current.children[part] = {
                    name: part,
                    path: relativePath,
                    type: 'file',
                    checked: true // Default: Encrypt
                };
            } else {
                // Folder
                if (!current.children[part]) {
                    current.children[part] = {
                        name: part,
                        path: current.path ? current.path + '/' + part : part,
                        type: 'folder',
                        children: {},
                        checked: true
                    };
                }
                current = current.children[part];
            }
        });
    });

    // Apply Default Exclusions (Manifest, Icons)
    const defaults = ["manifest.json", "pack_icon.png", "bug_pack_icon.png"];

    // Helper to uncheck specific files
    const applyDefaults = (node) => {
        if (node.type === 'file' && defaults.includes(node.name)) {
            node.checked = false;
        }
        if (node.type === 'folder') {
            Object.values(node.children).forEach(applyDefaults);
        }
    };
    Object.values(root.children).forEach(applyDefaults);

    // Render configuration
    dom.fileTreeContainer.innerHTML = '';

    // Sync checkboxes with default global checkboxes just for visual consistency? 
    // Actually, tree overrides global checkboxes. Let's hide global checkboxes or keep them synced? 
    // User requested "Select files to exclude". Tree is better.
    // We will IGNORE the top checkboxes if tree is active, or use tree as source of truth.
    // Let's rely on Tree as final truth.

    renderTreeItem(root, dom.fileTreeContainer);

    // Update global variables for encryption
    fileTreeData = root;
}

function renderTreeItem(node, container) {
    // Determine children
    const children = node.type === 'folder' ? Object.values(node.children) : [];
    const hasChildren = children.length > 0;

    // Container
    const itemDiv = document.createElement('div');
    itemDiv.className = 'tree-node';
    if (node.isRoot) itemDiv.setAttribute('data-root', 'true');

    // Content Row
    const contentDiv = document.createElement('div');
    contentDiv.className = 'tree-content';

    // Toggle Icon
    const toggle = document.createElement('div');
    toggle.className = `tree-toggle ${hasChildren ? '' : 'hidden'}`;
    toggle.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><path d="M7 10l5 5 5-5z"/></svg>';

    // Checkbox
    if (!node.isRoot) {
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'tree-checkbox';
        checkbox.checked = node.checked;

        checkbox.addEventListener('change', (e) => {
            const checked = e.target.checked;
            node.checked = checked;
            // Propagate down
            if (node.type === 'folder') {
                propagateCheck(node, checked);
                // Re-render children check state visually
                // Simple way: re-render this subtree or just hack DOM
                // Let's re-render subtree for simplicity or query selectors
                const childDiv = itemDiv.querySelector('.tree-children');
                if (childDiv) {
                    const childBoxes = childDiv.querySelectorAll('input[type="checkbox"]');
                    childBoxes.forEach(box => {
                        box.checked = checked;
                        // Update model data? handled by render logic? 
                        // We need to update data model recursively too.
                    });
                }
            }
            // Propagate Up? (Indeterminate state logic is complex, skipping for MVP)
        });
        contentDiv.appendChild(checkbox);
    } else {
        // Root doesn't have checkbox usually, or acts as "Select All"
    }

    // Icon
    const icon = document.createElement('div');
    icon.className = 'tree-icon';
    if (node.type === 'folder') {
        icon.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>';
        icon.style.color = '#f59e0b';
    } else {
        icon.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.89 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>';
        icon.style.color = '#3b82f6';
    }

    // Label
    const label = document.createElement('span');
    label.className = 'tree-label';
    label.textContent = node.name;

    // Assembly
    contentDiv.appendChild(toggle);
    if (!node.isRoot) contentDiv.appendChild(icon);
    else contentDiv.querySelector('.tree-toggle').style.display = 'none'; // No toggle for root visual if we just loop children

    contentDiv.appendChild(label);
    if (!node.isRoot) itemDiv.appendChild(contentDiv);

    // Children Container
    if (hasChildren) {
        const childrenContainer = document.createElement('div');
        childrenContainer.className = 'tree-children';

        // Sorting: Folders first, then Files
        children.sort((a, b) => {
            if (a.type === b.type) return a.name.localeCompare(b.name);
            return a.type === 'folder' ? -1 : 1;
        });

        children.forEach(child => renderTreeItem(child, childrenContainer));
        itemDiv.appendChild(childrenContainer);

        // Toggle Logic
        contentDiv.addEventListener('click', (e) => {
            if (e.target.type === 'checkbox') return;
            toggle.classList.toggle('collapsed');
            childrenContainer.classList.toggle('hidden');
        });

        if (node.isRoot) {
            // Unwrap root: just show children
            container.appendChild(childrenContainer);
            childrenContainer.style.marginLeft = "0";
            childrenContainer.style.borderLeft = "none";
            return;
        }
    }

    container.appendChild(itemDiv);
}

function propagateCheck(node, state) {
    node.checked = state;
    if (node.children) {
        Object.values(node.children).forEach(child => propagateCheck(child, state));
    }
}

function toggleTreeAll(expand) {
    const childrenDivs = dom.fileTreeContainer.querySelectorAll('.tree-children');
    const toggles = dom.fileTreeContainer.querySelectorAll('.tree-toggle');

    childrenDivs.forEach(el => {
        if (expand) el.classList.remove('hidden');
        else el.classList.add('hidden');
    });

    toggles.forEach(el => {
        if (expand) el.classList.remove('collapsed');
        else el.classList.add('collapsed');
    });
}

// --- Encryption Logic ---

async function startProcess() {
    const t = i18n[currentLang];

    try {
        // ... (Key Logic Same) ...
        let masterKey;
        let isManual = false;
        Array.from(dom.keyModeRadios).every(r => {
            if (r.checked && r.value === 'manual') isManual = true;
            return true;
        });
        if (isManual) {
            masterKey = dom.manualKeyInput.value.trim();
            if (masterKey.length !== 32) {
                showStatus(t.error_key_length, 'error');
                return;
            }
        } else {
            masterKey = randomKey(KEY_LENGTH);
        }

        // Determine Exclusions from Tree Data
        // Traverse fileTreeData
        const excludedPaths = new Set();

        const traverseExclusions = (node) => {
            if (node.type === 'file' && !node.checked) {
                // If unchecked, it is excluded
                excludedPaths.add(node.path);
            }
            if (node.children) {
                Object.values(node.children).forEach(traverseExclusions);
            }
        };
        // root is fileTreeData
        // Actually fileTreeData might be the root node
        if (fileTreeData && fileTreeData.children) {
            Object.values(fileTreeData.children).forEach(traverseExclusions);
        }

        dom.submitBtn.disabled = true;
        dom.btnText.textContent = t.btn_processing;

        // Load Zip (Actual Data)
        let loadedZip;
        let rootName = "resource_pack";

        if (currentMode === 'zip') {
            showStatus(t.status_read_zip, 'success');
            updateProgress(5, t.status_read_zip);
            const zip = new JSZip();
            loadedZip = await zip.loadAsync(currentFiles);
            rootName = currentFiles.name.replace('.zip', '');
        } else {
            showStatus(t.status_read_folder, 'success');
            updateProgress(5, t.status_read_folder);

            loadedZip = new JSZip();
            if (currentFiles[0] && currentFiles[0].webkitRelativePath) {
                rootName = currentFiles[0].webkitRelativePath.split('/')[0];
            }

            for (const file of currentFiles) {
                const parts = file.webkitRelativePath.split('/');
                const relativePath = parts.slice(1).join('/');
                if (relativePath) {
                    loadedZip.file(relativePath, file);
                }
            }
        }

        const outZip = new JSZip();

        let uuid = "00000000-0000-0000-0000-000000000000";
        const files = [];
        loadedZip.forEach((path, file) => { if (!file.dir) files.push(path); });

        const manifestEntry = files.find(n => n.endsWith('manifest.json'));
        if (manifestEntry) {
            try {
                const content = await loadedZip.file(manifestEntry).async('string');
                const json = JSON.parse(content);
                if (json.header && json.header.uuid) uuid = json.header.uuid;
            } catch (e) {
                console.warn("UUID detect failed");
            }
        }

        const rootFiles = [];
        const subpackFiles = {};

        files.forEach(name => {
            const clean = name.replace(/\\/g, '/');
            if (clean.startsWith('subpacks/')) {
                const parts = clean.split('/');
                if (parts.length >= 3) {
                    const root = parts.slice(0, 2).join('/') + '/';
                    if (!subpackFiles[root]) subpackFiles[root] = [];
                    subpackFiles[root].push(clean);
                    return;
                }
            }
            rootFiles.push(clean);
        });

        let processed = 0;
        const total = files.length;

        const processList = async (list, isSubpack, rootPath = "") => {
            const entries = [];
            for (const name of list) {
                const data = await loadedZip.file(name).async('uint8array');

                // Check Encryption Status
                // Does excludedPaths contain this path?
                const isExcluded = excludedPaths.has(name);

                if (!isSubpack && isExcluded) {
                    outZip.file(name, data);
                } else {
                    // Note: logic in Python script: IF subpack, we always encrypt? 
                    // Or do we support exclusions inside subpacks too?
                    // Python script: `if file in opts.excluded_files: copy`
                    // The user wants to exclude specific files.
                    // The requirement: "Select files to encrypt"
                    // If I Uncheck a file inside subpacks, it should NOT be encrypted.
                    // But the `contents_json` structure for subpacks might require keys?
                    // AES-CFB encryption usually implies everything listed in contents.json is encrypted?
                    // Wait, if I include it in contents.json, it MUST be encrypted with a key?
                    // Or can I have plaintext files in contents.json?
                    // Standard: contents.json maps path -> key.
                    // If file is not encrypted, it should probably NOT be in contents.json?
                    // OR it should be just copied to zip and NOT added to contents.json?
                    // Python script: `if file in opts.excluded_files: zout.writestr(...)` and `continue` (Skip adding to content_entries).
                    // So yes, excluded files are NOT in contents.json.

                    if (isExcluded) {
                        // Even if subpack, if excluded, just copy text?
                        // Subpacks have their own contents.json.
                        // If I exclude a file in subpack, it won't be in subpack's contents.json.
                        // This seems correct.
                        outZip.file(name, data);
                    } else {
                        const key = randomKey(KEY_LENGTH);
                        const enc = encryptBytes(data, key);
                        outZip.file(name, enc);

                        let rel = name;
                        if (isSubpack) rel = name.substring(rootPath.length);
                        entries.push({ path: rel, key: key });
                    }
                }

                processed++;
                if (processed % 10 === 0) {
                    updateProgress((processed / total) * 85, t.status_encrypt);
                    await new Promise(r => setTimeout(r, 0));
                }
            }
            return entries;
        };

        const rootCont = await processList(rootFiles, false);
        await writeContents(outZip, "contents.json", uuid, masterKey, rootCont);

        for (const root of Object.keys(subpackFiles)) {
            const subCont = await processList(subpackFiles[root], true, root);
            await writeContents(outZip, root + "contents.json", uuid, masterKey, subCont);
        }

        updateProgress(90, t.status_compress);

        const encryptedBlob = await outZip.generateAsync({ type: "blob" });
        const keyBlob = new Blob([masterKey], { type: "text/plain;charset=utf-8" });
        const infoBlob = new Blob([`UUID: ${uuid}\nGenerated by Web Encryptor`], { type: "text/plain;charset=utf-8" });

        const finalZip = new JSZip();
        finalZip.file(`${rootName}_encrypted.zip`, encryptedBlob);
        finalZip.file(`${rootName}.zip.key`, keyBlob);
        finalZip.file("info.txt", infoBlob);

        const resultBlob = await finalZip.generateAsync({ type: "blob" });

        updateProgress(100, t.status_done);
        saveAs(resultBlob, `${rootName}_bundle.zip`);

        showStatus(t.status_success, 'success');
        dom.btnText.textContent = t.btn_start;
        dom.submitBtn.disabled = false;

    } catch (e) {
        console.error(e);
        showStatus('Error: ' + e.message, 'error');
        dom.btnText.textContent = t.btn_retry;
        dom.submitBtn.disabled = false;
    }
}

// ... (Helper functions remain same) ...

function randomKey(length) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
    return result;
}

function stringToBytes(str) { return new TextEncoder().encode(str); }

function encryptBytes(data, keyStr) {
    const keyBytes = stringToBytes(keyStr);
    const ivBytes = keyBytes.slice(0, 16);
    const aesEcb = new aesjs.ModeOfOperation.ecb(keyBytes);
    const output = new Uint8Array(data.length);
    const shiftRegister = new Uint8Array(16);
    shiftRegister.set(ivBytes);

    for (let i = 0; i < data.length; i++) {
        const encryptedBlock = aesEcb.encrypt(shiftRegister);
        const keyStreamByte = encryptedBlock[0];
        output[i] = data[i] ^ keyStreamByte;
        shiftRegister.set(shiftRegister.subarray(1), 0);
        shiftRegister[15] = output[i];
    }
    return output;
}

async function writeContents(zip, name, uuid, key, entries) {
    const parts = [VERSION, MAGIC, new Uint8Array(8)];

    const cid = stringToBytes(uuid);
    parts.push(new Uint8Array([cid.length]));
    parts.push(cid);

    const padLen = 256 - (16 + 1 + cid.length);
    if (padLen > 0) parts.push(new Uint8Array(padLen));

    const headLen = parts.reduce((a, b) => a + b.length, 0);
    const header = new Uint8Array(headLen);
    let off = 0;
    parts.forEach(p => { header.set(p, off); off += p.length; });

    const jsonKey = stringToBytes(JSON.stringify({ content: entries }));
    const encryptedBody = encryptBytes(jsonKey, key);

    const final = new Uint8Array(header.length + encryptedBody.length);
    final.set(header, 0);
    final.set(encryptedBody, header.length);

    zip.file(name, final);
}

// Start
init();
