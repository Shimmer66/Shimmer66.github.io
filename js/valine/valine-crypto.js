/**
 * Valine Crypto Extension
 * An extension to enable encrypted comments in Valine
 */

(function() {
    // Crypto utilities using SubtleCrypto API
    const CryptoUtils = {

        
        // Import a key from base64 string
        importKey: async function(keyBase64) {
            try {
                const keyData = this.base64ToArrayBuffer(keyBase64);
                return await window.crypto.subtle.importKey(
                    "raw",
                    keyData,
                    {
                        name: "AES-GCM",
                        length: 256
                    },
                    false,
                    ["encrypt", "decrypt"]
                );
            } catch (error) {
                console.error("Failed to import key:", error);
                return null;
            }
        },
        
        // Encrypt a string with AES-GCM
        encrypt: async function(text, keyBase64) {
            try {
                // Try standard Web Crypto API
                const key = await this.importKey(keyBase64);
                if (!key) {
                    throw new Error("Failed to import key");
                }
                
                const encoder = new TextEncoder();
                const data = encoder.encode(text);
                
                // Generate random IV
                const iv = window.crypto.getRandomValues(new Uint8Array(12));
                
                const encrypted = await window.crypto.subtle.encrypt(
                    {
                        name: "AES-GCM",
                        iv: iv
                    },
                    key,
                    data
                );
                
                // Combine IV and encrypted data
                const result = new Uint8Array(iv.length + encrypted.byteLength);
                result.set(iv, 0);
                result.set(new Uint8Array(encrypted), iv.length);
                
                return this.arrayBufferToBase64(result);
            } catch (error) {
                console.error("Encryption failed, using fallback:", error);
                return this.fallbackEncrypt(text, keyBase64);
            }
        },
        
        // Fallback encryption method using a simpler approach
        fallbackEncrypt: function(text, keyBase64) {
            try {
                // Simple XOR-based encryption with the key
                const key = atob(keyBase64);
                let result = "";
                
                // 处理Unicode字符
                const textToEncode = unescape(encodeURIComponent(text));
                
                for (let i = 0; i < textToEncode.length; i++) {
                    const charCode = textToEncode.charCodeAt(i) ^ key.charCodeAt(i % key.length);
                    result += String.fromCharCode(charCode);
                }
                // Add a simple marker and return base64 encoded
                return btoa("FALLBACK:" + result);
            } catch (error) {
                console.error("Fallback encryption failed:", error);
                throw new Error("加密失败: " + error.message);
            }
        },
        
        // Decrypt a string with AES-GCM or fallback
        decrypt: async function(encryptedBase64, keyBase64) {
            try {
                // Check if it's fallback encrypted
                if (encryptedBase64.startsWith("RkFMTEJBQ0s6")) { // Base64 for "FALLBACK:"
                    return this.fallbackDecrypt(encryptedBase64, keyBase64);
                }
                
                const key = await this.importKey(keyBase64);
                if (!key) {
                    throw new Error("Failed to import key");
                }
                
                // Make sure we're working with valid Base64
                // Remove any whitespace or newlines that might have been added
                encryptedBase64 = encryptedBase64.trim().replace(/\s/g, '');
                
                try {
                    // Test if the string is valid base64
                    this.base64ToArrayBuffer(encryptedBase64);
                } catch (e) {
                    console.error('Invalid Base64 string:', e);
                    throw new Error("无效的Base64字符串");
                }
                
                const encryptedData = this.base64ToArrayBuffer(encryptedBase64);
                
                // Extract IV from the beginning of the data
                const iv = encryptedData.slice(0, 12);
                const data = encryptedData.slice(12);
                
                console.log("正在使用WebCrypto API解密...");
                
                const decrypted = await window.crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: iv
                    },
                    key,
                    data
                );
                
                const decoder = new TextDecoder('utf-8');
                return decoder.decode(decrypted);
            } catch (error) {
                console.error('解密失败:', error);
                // More detailed logging to help diagnose the issue
                console.log('加密数据:', encryptedBase64.substring(0, 20) + '...');
                console.log('使用的密钥(前几个字符):', keyBase64.substring(0, 5) + '...');
                
                // 尝试使用备用方法解密
                try {
                    console.log("尝试使用备用方法解密...");
                    return this.fallbackDecrypt(encryptedBase64, keyBase64);
                } catch (fallbackError) {
                    console.error("备用解密也失败:", fallbackError);
                    return null;
                }
            }
        },
        
        // Fallback decryption method
        fallbackDecrypt: function(encryptedBase64, keyBase64) {
            try {
                const key = atob(keyBase64);
                const decoded = atob(encryptedBase64);
                // Remove the "FALLBACK:" prefix
                const encryptedText = decoded.substring(9);
                
                let result = "";
                for (let i = 0; i < encryptedText.length; i++) {
                    const charCode = encryptedText.charCodeAt(i) ^ key.charCodeAt(i % key.length);
                    result += String.fromCharCode(charCode);
                }
                
                // 处理Unicode字符
                return decodeURIComponent(escape(result));
            } catch (error) {
                console.error("Fallback decryption failed:", error);
                return null;
            }
        },
        

        
        // Convert ArrayBuffer to Base64 string
        arrayBufferToBase64: function(buffer) {
            try {
                const bytes = new Uint8Array(buffer);
                let binary = '';
                for (let i = 0; i < bytes.byteLength; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                // 使用btoa前确保字符在Latin1范围内
                return window.btoa(binary);
            } catch (error) {
                console.error("Error converting ArrayBuffer to Base64:", error);
                throw error;
            }
        },
        
        // Convert Base64 string to ArrayBuffer
        base64ToArrayBuffer: function(base64) {
            try {
                // Remove any whitespace from the base64 string
                base64 = base64.trim().replace(/\s/g, '');
                
                // 确保base64字符串有效
                try {
                    const binaryString = window.atob(base64);
                    const len = binaryString.length;
                    const bytes = new Uint8Array(len);
                    for (let i = 0; i < len; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }
                    return bytes;
                } catch (e) {
                    console.error("Invalid Base64 string:", e);
                    throw new Error("无效的Base64字符串: " + e.message);
                }
            } catch (error) {
                console.error("Error converting Base64 to ArrayBuffer:", error);
                throw error;
            }
        },
        

    };

    // ValineCrypto Extension
    window.ValineCrypto = {
        initialized: false,

        observerInitialized: false,
        
        // Initialize the crypto extension
        init: function() {
            if (this.initialized) return;
            
            // 确保FontAwesome已加载，如果没有则添加
            if (!document.querySelector('link[href*="font-awesome"]')) {
                const fontAwesome = document.createElement('link');
                fontAwesome.rel = 'stylesheet';
                fontAwesome.href = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css';
                document.head.appendChild(fontAwesome);
                console.log("已添加FontAwesome图标库");
            }
            
            // Add CSS for encrypted comment UI
            const style = document.createElement('style');
            style.textContent = `
                .v-encrypted-badge {
                    display: inline-block;
                    margin-left: 5px;
                    padding: 0px 5px;
                    font-size: 12px;
                    color: #fff;
                    background-color: #f56c6c;
                    border-radius: 3px;
                }
                .v-encrypted-comment {
                    background-color: #f9f9f9;
                    padding: 8px;
                    border-radius: 4px;
                    border-left: 3px solid #f56c6c;
                }
                .v-encrypt-checkbox {
                    margin-right: 5px;
                    transform: scale(1.2);
                }
                .v-encrypt-label {
                    display: flex;
                    align-items: center;
                    margin: 8px 0;
                    padding: 5px 10px;
                    font-size: 14px;
                    color: #555;
                    background-color: #f8f8f8;
                    border: 1px dashed #ddd;
                    border-radius: 4px;
                    cursor: pointer;
                    transition: all 0.3s;
                }
                .v-encrypt-label:hover {
                    border-color: #f56c6c;
                    color: #f56c6c;
                }
                .v-encrypt-label.active {
                    background-color: #fff0f0;
                    border-color: #f56c6c;
                    color: #f56c6c;
                }
            `;
            document.head.appendChild(style);
            
            // Get fixed key from window object
            // This will be set in the Valine initialization
            this.accessKey = window.VALINE_COMMENT_KEY || '';
            
            if (this.accessKey) {
                console.log("Valine Crypto: Successfully initialized with key [有效密钥]");
            } else {
                console.warn("Valine Crypto: No valid encryption key found!");
            }
            
            this.initialized = true;
            
            // 在控制台输出帮助信息
            console.info("%c🔐 Valine评论加密系统已启动", "font-size:14px;color:#f56c6c;");
            console.info("%c如果没有看到私密评论选项，请按Ctrl+Shift+E尝试手动初始化", "color:#666;");
        },
        
        // Add encryption UI to Valine comment form
        enhanceValineForm: function(valineContainer) {
            this.init();
            
            // Check if encryption checkbox already exists to avoid duplicates
            if (valineContainer.querySelector('.v-encrypt-checkbox')) {
                return;
            }
            
            const submitBtn = valineContainer.querySelector('.vsubmit');
            if (!submitBtn) {
                console.warn("未找到提交按钮，无法添加加密选项");
                return;
            }
            
            console.log("正在添加私密评论选项...");
            
            // Create encryption checkbox only if we have a key configured
            if (this.accessKey) {
                const encryptLabel = document.createElement('label');
                encryptLabel.className = 'v-encrypt-label';
                
                const encryptCheckbox = document.createElement('input');
                encryptCheckbox.type = 'checkbox';
                encryptCheckbox.className = 'v-encrypt-checkbox';
                encryptCheckbox.id = 'v-encrypt-checkbox';
                
                const lockIcon = document.createElement('i');
                lockIcon.className = 'fas fa-lock';
                lockIcon.style.marginRight = '5px';
                
                encryptLabel.appendChild(encryptCheckbox);
                encryptLabel.appendChild(lockIcon);
                encryptLabel.appendChild(document.createTextNode('私密评论'));
                
                // Insert before submit button
                submitBtn.parentNode.insertBefore(encryptLabel, submitBtn);
                
                // Add checkbox change event to update label style
                encryptCheckbox.addEventListener('change', function() {
                    if (this.checked) {
                        encryptLabel.classList.add('active');
                    } else {
                        encryptLabel.classList.remove('active');
                    }
                });
                
                if (submitBtn._valineCryptoEnhanced) {
                    console.log('提交按钮已经被增强过，跳过重复处理');
                    return;
                }
                submitBtn._valineCryptoEnhanced = true;
                
                // 使用事件捕获来拦截点击事件
                submitBtn.addEventListener('click', async function(e) {
                    const isEncrypted = encryptCheckbox.checked;
                    const textareaElement = valineContainer.querySelector('.veditor');
                    
                    if (!textareaElement) {
                        console.error("找不到评论输入框");
                        return;
                    }
                    
                    const commentText = textareaElement.value.trim();
                    if (!commentText) {
                        console.warn("评论内容为空");
                        return;
                    }
                    
                    if (isEncrypted) {
                        // 阻止默认提交，先进行加密处理
                        e.preventDefault();
                        e.stopPropagation();
                        e.stopImmediatePropagation();
                        
                        try {
                            console.log("正在加密评论...");
                            
                            // 执行加密
                            const encryptedText = await CryptoUtils.encrypt(commentText, ValineCrypto.accessKey);
                            if (!encryptedText) {
                                throw new Error("加密过程返回空结果");
                            }
                            
                            console.log("加密成功，加密后的数据长度：", encryptedText.length);
                            
                            // 将加密后的内容设置到输入框，使用特殊标记
                            textareaElement.value = '[加密评论]' + encryptedText;
                            
                            console.log("评论已加密，准备提交...");
                            
                            // 清除加密选项状态
                            encryptCheckbox.checked = false;
                            encryptLabel.classList.remove('active');
                            
                            // 直接调用表单提交，绕过事件系统
                            const form = textareaElement.closest('form') || textareaElement.closest('.vwrap');
                            if (form) {
                                // 查找表单中的提交按钮并直接触发其原始功能
                                const formSubmitBtn = form.querySelector('.vsubmit') || form.querySelector('button[type="submit"]') || submitBtn;
                                
                                // 临时移除我们的事件监听器
                                const tempHandler = arguments.callee;
                                formSubmitBtn.removeEventListener('click', tempHandler, true);
                                
                                // 创建一个新的点击事件并直接分发
                                setTimeout(() => {
                                    const clickEvent = new MouseEvent('click', {
                                        bubbles: true,
                                        cancelable: true,
                                        view: window
                                    });
                                    
                                    formSubmitBtn.click();
                                    
                                    // 重新添加我们的事件监听器
                                    setTimeout(() => {
                                        formSubmitBtn.addEventListener('click', tempHandler, true);
                                    }, 100);
                                    
                                    // 提交后等待评论区更新，再处理评论
                                    setTimeout(() => {
                                        console.log("重新处理评论区以显示新提交的加密评论");
                                        ValineCrypto.processComments(valineContainer);
                                    }, 2000);
                                }, 50);
                            }
                            
                        } catch (error) {
                            console.error('加密失败:', error);
                            alert('评论加密失败: ' + error.message);
                            return false;
                        }
                    }
                    
                    // 如果没有加密，让Valine正常处理提交流程
                    console.log("评论准备提交，内容长度：", textareaElement.value.length);
                }, true); // 使用捕获阶段
                
                console.log("私密评论选项已添加，提交按钮事件已重绑定");
            } else {
                console.warn("没有配置有效的加密密钥，无法启用私密评论功能");
            }
        },
        
        // Add decrypt button to encrypted comments
        addDecryptButton: function(commentElement, contentElement, content) {
            // Check if decrypt button already exists
            if (commentElement.querySelector('.decrypt-btn')) {
                return;
            }
            
            // 提取加密数据，支持多种格式
            let encryptedData = '';
            if (content.includes('[encrypted]')) {
                encryptedData = content.replace('[encrypted]', '').trim();
            } else if (content.includes('[加密评论]')) {
                encryptedData = content.replace('[加密评论]', '').trim();
            }
            
            if (!encryptedData) {
                console.warn('无法提取加密数据');
                return;
            }
            
            // Replace content with encrypted message and decrypt button
            contentElement.innerHTML = `
                <div class="v-encrypted-comment">
                    <span class="v-encrypted-badge">🔒 加密评论</span>
                    <p style="margin: 8px 0; color: #666;">此评论已加密，需要密钥才能查看</p>
                    <button class="decrypt-btn" style="
                        background: #f56c6c;
                        color: white;
                        border: none;
                        padding: 5px 10px;
                        border-radius: 3px;
                        cursor: pointer;
                        font-size: 12px;
                    ">🔓 解锁查看</button>
                </div>
            `;
            
            const decryptBtn = contentElement.querySelector('.decrypt-btn');
            decryptBtn.addEventListener('click', async () => {
                try {
                    const decryptedText = await CryptoUtils.decrypt(encryptedData, this.accessKey);
                    if (decryptedText) {
                        contentElement.innerHTML = `<div class="decrypted-content">${decryptedText}</div>`;
                        console.log("评论解密成功");
                    } else {
                        throw new Error("解密失败");
                    }
                } catch (error) {
                    console.error('解密失败:', error);
                    alert('解密失败，请检查密钥是否正确');
                }
            });
        },
        
        // Process comments to decrypt any encrypted ones
        processComments: function(commentsContainer) {
            this.init();
            
            // If no access key, we can't decrypt
            if (!this.accessKey) {
                console.log("No access key available for decryption");
                return;
            }
            
            // Find all comments that haven't been processed yet
            const unprocessedComments = Array.from(commentsContainer.querySelectorAll('.vcontent')).filter(
                comment => !comment.hasAttribute('data-crypto-processed')
            );
            
            console.log(`Processing ${unprocessedComments.length} unprocessed comments`);
            
            // 添加密钥输入界面（如果尚未添加）
            if (!document.getElementById('valine-crypto-key-input')) {
                this.addKeyInputInterface(commentsContainer);
            }
            
            // 创建一个全局解锁按钮，用于解锁所有评论
            if (!document.getElementById('global-unlock-button') && unprocessedComments.some(comment => {
                const text = comment.textContent.trim();
                return text.startsWith('[encrypted]') || text.startsWith('[加密评论]');
            })) {
                const globalUnlockBtn = document.createElement('button');
                globalUnlockBtn.id = 'global-unlock-button';
                globalUnlockBtn.className = 'v-crypto-global-unlock-btn';
                globalUnlockBtn.innerHTML = '<i class="fas fa-key"></i> 输入密钥查看加密评论';
                globalUnlockBtn.onclick = (e) => {
                    e.preventDefault();
                    // 显示密钥输入界面
                    const keyInput = document.getElementById('valine-crypto-key-input');
                    if (keyInput) {
                        keyInput.style.display = 'block';
                        keyInput.querySelector('input').focus();
                        keyInput.setAttribute('data-target-comment', 'all');
                        
                        // 定位到页面中央
                        keyInput.style.position = 'fixed';
                        keyInput.style.top = '50%';
                        keyInput.style.left = '50%';
                        keyInput.style.transform = 'translate(-50%, -50%)';
                    }
                };
                
                // 添加到评论区顶部
                const commentHeader = commentsContainer.querySelector('.vcount') || commentsContainer.firstElementChild;
                if (commentHeader) {
                    commentHeader.parentNode.insertBefore(globalUnlockBtn, commentHeader.nextSibling);
                } else {
                    commentsContainer.insertBefore(globalUnlockBtn, commentsContainer.firstChild);
                }
            }
            
            unprocessedComments.forEach(async (comment) => {
                // Mark as processed to avoid reprocessing
                comment.setAttribute('data-crypto-processed', 'true');
                
                const commentText = comment.textContent.trim();
                
                // Check if comment is encrypted (支持多种加密标记)
                let encryptedData = null;
                if (commentText.startsWith('[encrypted]')) {
                    encryptedData = commentText.substring('[encrypted]'.length);
                } else if (commentText.startsWith('[加密评论]')) {
                    encryptedData = commentText.substring('[加密评论]'.length);
                }
                
                if (encryptedData) {
                    console.log("Found encrypted comment");
                    
                    // Store original encrypted text before replacing it
                    comment.setAttribute('data-encrypted-content', encryptedData);
                    
                    // Add encrypted badge if not already added
                    if (!comment.nextElementSibling || !comment.nextElementSibling.classList.contains('v-encrypted-badge')) {
                        const badge = document.createElement('span');
                        badge.className = 'v-encrypted-badge';
                        badge.textContent = '私密评论';
                        comment.parentNode.insertBefore(badge, comment.nextSibling);
                    }
                    
                    // Add special styling to encrypted comments
                    comment.classList.add('v-encrypted-comment');
                    
                    // Always try to decrypt with our fixed key
                    try {
                        console.log("Attempting to decrypt with key");
                        const decryptedText = await CryptoUtils.decrypt(encryptedData, this.accessKey);
                        if (decryptedText) {
                            console.log("Decryption successful");
                            comment.textContent = decryptedText;
                            comment.setAttribute('data-crypto-decrypted', 'true');
                        } else {
                            console.log("Decryption returned null");
                            // 始终显示解锁按钮，无论是否解密成功
                            const unlockBtn = document.createElement('button');
                            unlockBtn.className = 'v-crypto-unlock-btn';
                            unlockBtn.innerHTML = '<i class="fas fa-key"></i> 输入密钥查看';
                            unlockBtn.onclick = (e) => {
                                e.preventDefault();
                                // 显示密钥输入界面并聚焦
                                const keyInput = document.getElementById('valine-crypto-key-input');
                                if (keyInput) {
                                    keyInput.style.display = 'block';
                                    keyInput.querySelector('input').focus();
                                    
                                    // 定位到页面中央而不是按钮下方
                                    keyInput.style.position = 'fixed';
                                    keyInput.style.top = '50%';
                                    keyInput.style.left = '50%';
                                    keyInput.style.transform = 'translate(-50%, -50%)';
                                    
                                    // 记录当前要解密的评论
                                    keyInput.setAttribute('data-target-comment', comment.getAttribute('data-crypto-id') || '');
                                }
                            };
                            
                            // 为每个加密评论添加唯一ID，方便解密时定位
                            const cryptoId = 'crypto-comment-' + Math.random().toString(36).substring(2, 15);
                            comment.setAttribute('data-crypto-id', cryptoId);
                            
                            comment.textContent = '此评论已加密，仅博主可见 ';
                            comment.appendChild(unlockBtn);
                            comment.setAttribute('data-crypto-decrypted', 'false');
                        }
                    } catch (error) {
                        console.error('Decryption failed:', error);
                        const unlockBtn = document.createElement('button');
                        unlockBtn.className = 'v-crypto-unlock-btn';
                        unlockBtn.innerHTML = '<i class="fas fa-key"></i> 输入密钥查看';
                        unlockBtn.onclick = (e) => {
                            e.preventDefault();
                            // 显示密钥输入界面
                            const keyInput = document.getElementById('valine-crypto-key-input');
                            if (keyInput) {
                                keyInput.style.display = 'block';
                                keyInput.querySelector('input').focus();
                                
                                // 定位到页面中央
                                keyInput.style.position = 'fixed';
                                keyInput.style.top = '50%';
                                keyInput.style.left = '50%';
                                keyInput.style.transform = 'translate(-50%, -50%)';
                                
                                // 记录当前要解密的评论
                                keyInput.setAttribute('data-target-comment', comment.getAttribute('data-crypto-id') || '');
                            }
                        };
                        
                        // 为每个加密评论添加唯一ID，方便解密时定位
                        const cryptoId = 'crypto-comment-' + Math.random().toString(36).substring(2, 15);
                        comment.setAttribute('data-crypto-id', cryptoId);
                        
                        comment.textContent = '此评论已加密，仅博主可见 ';
                        comment.appendChild(unlockBtn);
                        comment.setAttribute('data-crypto-decrypted', 'false');
                    }
                }
            });
        },
        
        // 添加密钥输入界面
        addKeyInputInterface: function(container) {
            // 检查是否已存在
            if (document.getElementById('valine-crypto-key-input')) {
                return;
            }
            
            console.log("添加密钥输入界面");
            
            // 创建密钥输入界面
            const keyInputDiv = document.createElement('div');
            keyInputDiv.id = 'valine-crypto-key-input';
            keyInputDiv.className = 'v-crypto-key-input';
            keyInputDiv.style.display = 'none';
            
            // 添加标题
            const title = document.createElement('h3');
            title.textContent = '请输入密钥查看私密评论';
            title.style.margin = '0 0 15px 0';
            title.style.padding = '0';
            title.style.fontSize = '16px';
            title.style.fontWeight = 'bold';
            title.style.color = '#333';
            
            // 创建输入框
            const input = document.createElement('input');
            input.type = 'password';
            input.placeholder = '请输入密钥解锁评论';
            
            // 添加密钥保存选项
            const saveKeyDiv = document.createElement('div');
            saveKeyDiv.style.margin = '10px 0';
            
            const saveKeyCheckbox = document.createElement('input');
            saveKeyCheckbox.type = 'checkbox';
            saveKeyCheckbox.id = 'save-key-checkbox';
            saveKeyCheckbox.style.marginRight = '5px';
            
            const saveKeyLabel = document.createElement('label');
            saveKeyLabel.htmlFor = 'save-key-checkbox';
            saveKeyLabel.textContent = '记住密钥（本地存储）';
            saveKeyLabel.style.fontSize = '12px';
            saveKeyLabel.style.color = '#666';
            
            saveKeyDiv.appendChild(saveKeyCheckbox);
            saveKeyDiv.appendChild(saveKeyLabel);
            
            // 创建解密按钮
            const decryptBtn = document.createElement('button');
            decryptBtn.textContent = '解锁';
            decryptBtn.onclick = async (e) => {
                e.preventDefault();
                const key = input.value.trim();
                if (!key) {
                    alert('请输入有效的密钥');
                    return;
                }
                
                // 保存密钥到本地存储（如果勾选了记住密钥）
                if (saveKeyCheckbox.checked) {
                    try {
                        localStorage.setItem('valine_crypto_key', key);
                        console.log('密钥已保存到本地存储');
                    } catch (error) {
                        console.error('保存密钥到本地存储失败:', error);
                    }
                }
                
                // 获取当前要解密的评论ID
                const targetCommentId = keyInputDiv.getAttribute('data-target-comment');
                
                // 检查是否要解密所有评论
                if (targetCommentId === 'all') {
                    // 解密所有加密评论
                    const encryptedComments = document.querySelectorAll('.v-encrypted-comment');
                    let successCount = 0;
                    
                    for (const comment of encryptedComments) {
                        const encryptedData = comment.getAttribute('data-encrypted-content');
                        if (!encryptedData) continue;
                        
                        try {
                            const decryptedText = await CryptoUtils.decrypt(encryptedData, key);
                            if (decryptedText) {
                                comment.textContent = decryptedText;
                                comment.setAttribute('data-crypto-decrypted', 'true');
                                successCount++;
                            }
                        } catch (error) {
                            console.error('解密评论失败:', error);
                        }
                    }
                    
                    keyInputDiv.style.display = 'none';
                    input.value = '';
                    
                    if (successCount > 0) {
                        alert(`成功解密 ${successCount} 条评论`);
                    } else {
                        alert('解密失败，请检查密钥是否正确');
                    }
                    
                    return;
                }
                
                // 单个评论解密
                if (!targetCommentId) {
                    alert('无法确定要解密的评论');
                    return;
                }
                
                // 查找目标评论
                const targetComment = document.querySelector(`[data-crypto-id="${targetCommentId}"]`);
                if (!targetComment) {
                    alert('找不到目标评论');
                    return;
                }
                
                // 获取加密数据
                const encryptedData = targetComment.getAttribute('data-encrypted-content');
                if (!encryptedData) {
                    alert('找不到加密数据');
                    return;
                }
                
                // 尝试解密
                try {
                    const decryptedText = await CryptoUtils.decrypt(encryptedData, key);
                    if (decryptedText) {
                        targetComment.textContent = decryptedText;
                        targetComment.setAttribute('data-crypto-decrypted', 'true');
                        keyInputDiv.style.display = 'none';
                        input.value = '';
                    } else {
                        alert('解密失败，请检查密钥是否正确');
                    }
                } catch (error) {
                    console.error('解密失败:', error);
                    alert('解密失败: ' + error.message);
                }
            };
            
            // 创建关闭按钮
            const closeBtn = document.createElement('button');
            closeBtn.textContent = '取消';
            closeBtn.onclick = (e) => {
                e.preventDefault();
                keyInputDiv.style.display = 'none';
                input.value = '';
            };
            
            // 按钮容器
            const buttonContainer = document.createElement('div');
            buttonContainer.style.display = 'flex';
            buttonContainer.style.justifyContent = 'flex-end';
            buttonContainer.style.marginTop = '15px';
            
            buttonContainer.appendChild(decryptBtn);
            buttonContainer.appendChild(closeBtn);
            
            // 组装界面
            keyInputDiv.appendChild(title);
            keyInputDiv.appendChild(input);
            keyInputDiv.appendChild(saveKeyDiv);
            keyInputDiv.appendChild(buttonContainer);
            
            // 添加到容器
            document.body.appendChild(keyInputDiv);
            
            // 尝试加载保存的密钥
            try {
                const savedKey = localStorage.getItem('valine_crypto_key');
                if (savedKey) {
                    input.value = savedKey;
                    saveKeyCheckbox.checked = true;
                    console.log('从本地存储加载了保存的密钥');
                }
            } catch (error) {
                console.error('从本地存储加载密钥失败:', error);
            }
            
            // 添加样式
            const style = document.createElement('style');
            style.textContent = `
                .v-crypto-key-input {
                    position: fixed;
                    z-index: 9999;
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.15);
                    border: 1px solid #ddd;
                    width: 320px;
                    max-width: 90%;
                }
                
                .v-crypto-key-input input {
                    padding: 10px 12px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    width: 100%;
                    box-sizing: border-box;
                    font-size: 14px;
                    margin-bottom: 10px;
                }
                
                .v-crypto-key-input button {
                    padding: 8px 16px;
                    border: none;
                    border-radius: 4px;
                    background: #f56c6c;
                    color: white;
                    cursor: pointer;
                    margin-left: 10px;
                    font-size: 14px;
                    transition: all 0.3s;
                }
                
                .v-crypto-key-input button:hover {
                    background: #e45c5c;
                }
                
                .v-crypto-key-input button:last-child {
                    background: #ddd;
                    color: #666;
                }
                
                .v-crypto-key-input button:last-child:hover {
                    background: #ccc;
                }
                
                .v-crypto-unlock-btn {
                    background: transparent;
                    color: #f56c6c;
                    border: 1px solid #f56c6c;
                    border-radius: 3px;
                    padding: 3px 8px;
                    font-size: 12px;
                    cursor: pointer;
                    margin-left: 10px;
                    transition: all 0.3s;
                }
                
                .v-crypto-unlock-btn:hover {
                    background: #f56c6c;
                    color: white;
                }
                
                .v-crypto-global-unlock-btn {
                    display: block;
                    margin: 10px 0;
                    padding: 8px 16px;
                    background: #f8f8f8;
                    color: #f56c6c;
                    border: 1px dashed #f56c6c;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 14px;
                    text-align: center;
                    width: 100%;
                    transition: all 0.3s;
                }
                
                .v-crypto-global-unlock-btn:hover {
                    background: #fff0f0;
                }
            `;
            document.head.appendChild(style);
        },
        
        // Setup mutation observer to watch for new comments
        setupObserver: function(valineContainer) {
            if (this.observerInitialized || !valineContainer) return;
            
            const observer = new MutationObserver((mutations) => {
                let shouldProcess = false;
                
                mutations.forEach((mutation) => {
                    if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                        shouldProcess = true;
                    }
                });
                
                if (shouldProcess) {
                    // Debounce the processing to avoid too many operations
                    clearTimeout(this.processTimeout);
                    this.processTimeout = setTimeout(() => {
                        this.processComments(valineContainer);
                    }, 500);
                }
            });
            
            observer.observe(valineContainer, { 
                childList: true, 
                subtree: true,
                attributes: false,
                characterData: false
            });
            
            this.observerInitialized = true;
        },
        
        // Check encryption status of comments
        getEncryptionStats: function(container) {
            const stats = {
                total: 0,
                encrypted: 0,
                decrypted: 0,
                failed: 0
            };
            
            const comments = container.querySelectorAll('.vcontent');
            stats.total = comments.length;
            
            comments.forEach(comment => {
                if (comment.classList.contains('v-encrypted-comment')) {
                    stats.encrypted++;
                    
                    const isDecrypted = comment.getAttribute('data-crypto-decrypted');
                    if (isDecrypted === 'true') {
                        stats.decrypted++;
                    } else if (isDecrypted === 'false') {
                        stats.failed++;
                    }
                }
            });
            
            return stats;
        }
    };

    // Helper to detect if Valine is loaded
    function isValineLoaded() {
        return typeof window.Valine === 'function' && document.querySelector('.v');
    }
    
    // Attempt counter to limit retries
    let attemptCount = 0;
    const MAX_ATTEMPTS = 5;
    
    // Initial check with increasing delay
    function initValineCrypto() {
        if (attemptCount >= MAX_ATTEMPTS) {
            console.log('Giving up on Valine initialization after ' + MAX_ATTEMPTS + ' attempts');
            return;
        }
        
        attemptCount++;
        
        if (isValineLoaded()) {
            const valineContainer = document.querySelector('.v');
            if (valineContainer) {
                console.log('Valine container found, enhancing with crypto capabilities');
                ValineCrypto.enhanceValineForm(valineContainer);
                ValineCrypto.processComments(valineContainer);
                ValineCrypto.setupObserver(valineContainer);
            }
        } else {
            console.log('Valine not ready yet, will retry in ' + (attemptCount * 1000) + 'ms');
            setTimeout(initValineCrypto, attemptCount * 1000); // Increasing delay
        }
    }
    
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            // Give Valine time to initialize
            setTimeout(initValineCrypto, 1000);
        });
    } else {
        // DOM already loaded, wait a bit for scripts to finish
        setTimeout(initValineCrypto, 1000);
    }
    
    // Backup plan: also check when window is fully loaded
    window.addEventListener('load', function() {
        setTimeout(initValineCrypto, 1500);
    });

    // 强制性检查，确保在页面完全加载后尝试再次初始化
    window.addEventListener('load', function() {
        // 延迟3秒，确保Valine完全加载
        setTimeout(function() {
            console.log("强制检查并初始化加密功能");
            const valineContainer = document.querySelector('.v');
            if (valineContainer) {
                ValineCrypto.enhanceValineForm(valineContainer);
                ValineCrypto.processComments(valineContainer);
                ValineCrypto.setupObserver(valineContainer);
            } else {
                console.warn("强制检查时未找到Valine容器");
            }
        }, 3000);
    });

    // 添加键盘事件监听，用于开发调试
    document.addEventListener('keydown', function(e) {
        // Ctrl+Shift+E 手动触发初始化
        if (e.ctrlKey && e.shiftKey && e.key === 'E') {
            console.log("手动触发加密功能初始化");
            const valineContainer = document.querySelector('.v');
            if (valineContainer) {
                ValineCrypto.enhanceValineForm(valineContainer);
                ValineCrypto.processComments(valineContainer);
                ValineCrypto.setupObserver(valineContainer);
            } else {
                console.warn("手动初始化时未找到Valine容器");
            }
        }
    });
})();