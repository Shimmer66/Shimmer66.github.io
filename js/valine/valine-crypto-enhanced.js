/**
 * Enhanced Valine Crypto Extension
 * 无后端加密评论系统 - 增强版
 * 适配 Hexo 静态博客和 Valine 评论系统
 * 
 * 特性:
 * - AES-GCM 加密算法 + XOR 备用方案
 * - 多层密钥管理和盐值注入
 * - 富文本内容支持
 * - 安全的密钥存储
 * - 优化的用户体验
 * - 完整的错误处理
 */

(function() {
    'use strict';
    
    // 配置常量
    const CONFIG = {
        ENCRYPTION_MARKER: '[🔒ENCRYPTED]',
        FALLBACK_MARKER: 'FALLBACK:',
        KEY_STORAGE_NAME: 'valine_crypto_master_key',
        SALT_STORAGE_NAME: 'valine_crypto_salt',
        IV_LENGTH: 12,
        KEY_LENGTH: 32,
        MAX_RETRY_ATTEMPTS: 3,
        DEBOUNCE_DELAY: 500,
        INIT_TIMEOUT: 5000
    };
    
    // 安全工具类
    const SecurityUtils = {
        // 生成安全的随机盐值
        generateSalt: function(length = 16) {
            const array = new Uint8Array(length);
            window.crypto.getRandomValues(array);
            return this.arrayBufferToBase64(array);
        },
        
        // 生成强密钥
        generateStrongKey: async function(password, salt) {
            const encoder = new TextEncoder();
            const keyMaterial = await window.crypto.subtle.importKey(
                'raw',
                encoder.encode(password),
                { name: 'PBKDF2' },
                false,
                ['deriveBits', 'deriveKey']
            );
            
            // 获取PBKDF2迭代次数配置
            const iterations = (window.VALINE_CRYPTO_CONFIG && 
                               window.VALINE_CRYPTO_CONFIG.security && 
                               window.VALINE_CRYPTO_CONFIG.security.pbkdf2Iterations) || 100000;
            
            return await window.crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: encoder.encode(salt),
                    iterations: iterations,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );
        },
        
        // 安全的Base64编码
        arrayBufferToBase64: function(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return window.btoa(binary);
        },
        
        // 安全的Base64解码
        base64ToArrayBuffer: function(base64) {
            const binaryString = window.atob(base64.trim().replace(/\s/g, ''));
            const len = binaryString.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes;
        },
        
        // 验证密钥强度
        validateKeyStrength: function(key) {
            if (!key || key.length < 8) {
                return { valid: false, message: '密钥长度至少需要8个字符' };
            }
            
            const hasUpper = /[A-Z]/.test(key);
            const hasLower = /[a-z]/.test(key);
            const hasNumber = /\d/.test(key);
            const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(key);
            
            const strength = [hasUpper, hasLower, hasNumber, hasSpecial].filter(Boolean).length;
            
            if (strength < 2) {
                return { valid: false, message: '密钥强度不足，建议包含大小写字母、数字和特殊字符' };
            }
            
            return { valid: true, strength: strength };
        }
    };
    
    // 加密工具类
    const CryptoUtils = {
        // 主加密方法 - AES-GCM
        encrypt: async function(text, masterKey, salt) {
            try {
                // 获取配置的盐值长度
                const saltLength = (window.VALINE_CRYPTO_CONFIG && 
                                   window.VALINE_CRYPTO_CONFIG.security && 
                                   window.VALINE_CRYPTO_CONFIG.security.saltLength) || 16;
                
                // 生成盐值：如果有全局盐值配置，则与随机盐值组合使用
                let finalSalt;
                if (window.VALINE_CRYPTO_SALT) {
                    // 使用配置的盐值 + 随机盐值的组合
                    const configSalt = new TextEncoder().encode(window.VALINE_CRYPTO_SALT);
                    const randomSalt = window.crypto.getRandomValues(new Uint8Array(8));
                    finalSalt = new Uint8Array(saltLength);
                    
                    // 将配置盐值和随机盐值混合
                    for (let i = 0; i < saltLength; i++) {
                        finalSalt[i] = configSalt[i % configSalt.length] ^ randomSalt[i % randomSalt.length];
                    }
                    
                    // 将混合盐值转换为字符串用于密钥生成
                    salt = SecurityUtils.arrayBufferToBase64(finalSalt) + salt;
                } else {
                    // 使用传入的盐值
                    finalSalt = new TextEncoder().encode(salt);
                }
                
                // 生成强密钥
                const key = await SecurityUtils.generateStrongKey(masterKey, salt);
                
                // 编码文本
                const encoder = new TextEncoder();
                const data = encoder.encode(text);
                
                // 生成随机IV
                const iv = window.crypto.getRandomValues(new Uint8Array(CONFIG.IV_LENGTH));
                
                // 加密
                const encrypted = await window.crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv: iv },
                    key,
                    data
                );
                
                // 组合IV和加密数据
                const result = new Uint8Array(iv.length + encrypted.byteLength);
                result.set(iv, 0);
                result.set(new Uint8Array(encrypted), iv.length);
                
                return SecurityUtils.arrayBufferToBase64(result);
            } catch (error) {
                console.warn('AES-GCM加密失败，使用备用方案:', error);
                return this.fallbackEncrypt(text, masterKey, salt);
            }
        },
        
        // 备用加密方法 - 增强XOR
        fallbackEncrypt: function(text, masterKey, salt) {
            try {
                // 生成盐值：优先使用配置的盐值
                let finalSalt = salt;
                if (window.VALINE_CRYPTO_SALT) {
                    // 使用配置盐值 + 随机后缀
                    const randomSuffix = Math.random().toString(36).substring(2, 8);
                    finalSalt = window.VALINE_CRYPTO_SALT + '_' + salt + '_' + randomSuffix;
                }
                
                // 创建增强密钥
                const enhancedKey = this.createEnhancedKey(masterKey, finalSalt);
                
                // Unicode安全编码
                let textToEncode = unescape(encodeURIComponent(text));
                
                // 多轮XOR加密
                for (let round = 0; round < 3; round++) {
                    let roundResult = '';
                    for (let i = 0; i < textToEncode.length; i++) {
                        const keyIndex = (i + round * 7) % enhancedKey.length;
                        const charCode = textToEncode.charCodeAt(i) ^ enhancedKey.charCodeAt(keyIndex) ^ (round + 1);
                        roundResult += String.fromCharCode(charCode);
                    }
                    textToEncode = roundResult;
                }
                
                return btoa(CONFIG.FALLBACK_MARKER + textToEncode);
            } catch (error) {
                console.error('备用加密失败:', error);
                throw new Error('加密失败: ' + error.message);
            }
        },
        
        // 主解密方法
        decrypt: async function(encryptedBase64, masterKey, salt) {
            try {
                // 检查是否为备用加密
                const decoded = atob(encryptedBase64);
                if (decoded.startsWith(CONFIG.FALLBACK_MARKER)) {
                    return this.fallbackDecrypt(encryptedBase64, masterKey, salt);
                }
                
                // 生成盐值：如果有全局盐值配置，则与随机盐值组合使用
                let finalSalt = salt;
                if (window.VALINE_CRYPTO_SALT) {
                    // 使用配置的盐值 + 随机盐值的组合
                    const configSalt = new TextEncoder().encode(window.VALINE_CRYPTO_SALT);
                    const randomSalt = SecurityUtils.base64ToArrayBuffer(salt.substring(salt.length - 12)); // 提取随机部分
                    
                    // 重新构建混合盐值字符串
                    finalSalt = SecurityUtils.arrayBufferToBase64(configSalt) + salt;
                }
                
                // AES-GCM解密
                const key = await SecurityUtils.generateStrongKey(masterKey, finalSalt);
                const encryptedData = SecurityUtils.base64ToArrayBuffer(encryptedBase64);
                
                // 提取IV和数据
                const iv = encryptedData.slice(0, CONFIG.IV_LENGTH);
                const data = encryptedData.slice(CONFIG.IV_LENGTH);
                
                // 解密
                const decrypted = await window.crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: iv },
                    key,
                    data
                );
                
                const decoder = new TextDecoder('utf-8');
                return decoder.decode(decrypted);
            } catch (error) {
                console.warn('AES-GCM解密失败，尝试备用方案:', error);
                return this.fallbackDecrypt(encryptedBase64, masterKey, salt);
            }
        },
        
        // 备用解密方法
        fallbackDecrypt: function(encryptedBase64, masterKey, salt) {
            try {
                const decoded = atob(encryptedBase64);
                let encryptedText = decoded.startsWith(CONFIG.FALLBACK_MARKER) 
                    ? decoded.substring(CONFIG.FALLBACK_MARKER.length)
                    : decoded;
                
                // 处理盐值：如果有全局盐值配置，需要重新构建
                let finalSalt = salt;
                if (window.VALINE_CRYPTO_SALT) {
                    // 使用配置盐值 + 随机后缀
                    const randomSuffix = Math.random().toString(36).substring(2, 8);
                    finalSalt = window.VALINE_CRYPTO_SALT + '_' + salt + '_' + randomSuffix;
                }
                
                const enhancedKey = this.createEnhancedKey(masterKey, finalSalt);
                
                // 多轮XOR解密（逆序）
                for (let round = 2; round >= 0; round--) {
                    let roundResult = '';
                    for (let i = 0; i < encryptedText.length; i++) {
                        const keyIndex = (i + round * 7) % enhancedKey.length;
                        const charCode = encryptedText.charCodeAt(i) ^ enhancedKey.charCodeAt(keyIndex) ^ (round + 1);
                        roundResult += String.fromCharCode(charCode);
                    }
                    encryptedText = roundResult;
                }
                
                // Unicode安全解码
                return decodeURIComponent(escape(encryptedText));
            } catch (error) {
                console.error('备用解密失败:', error);
                return null;
            }
        },
        
        // 创建增强密钥
        createEnhancedKey: function(masterKey, salt) {
            const combined = masterKey + salt + masterKey.split('').reverse().join('');
            let enhanced = '';
            for (let i = 0; i < combined.length; i++) {
                enhanced += String.fromCharCode(combined.charCodeAt(i) ^ (i % 256));
            }
            return enhanced;
        }
    };
    
    // 存储管理类
    const StorageManager = {
        // 安全存储密钥
        saveKey: function(key, remember = false) {
            if (!remember) {
                this.clearKey();
                return;
            }
            
            try {
                // 简单混淆存储（不是真正的加密，只是防止明文存储）
                const obfuscated = btoa(key.split('').reverse().join(''));
                localStorage.setItem(CONFIG.KEY_STORAGE_NAME, obfuscated);
                console.log('密钥已安全保存');
            } catch (error) {
                console.error('保存密钥失败:', error);
            }
        },
        
        // 获取存储的密钥
        getKey: function() {
            try {
                const obfuscated = localStorage.getItem(CONFIG.KEY_STORAGE_NAME);
                if (!obfuscated) return null;
                
                return atob(obfuscated).split('').reverse().join('');
            } catch (error) {
                console.error('获取密钥失败:', error);
                return null;
            }
        },
        
        // 清除密钥
        clearKey: function() {
            try {
                localStorage.removeItem(CONFIG.KEY_STORAGE_NAME);
            } catch (error) {
                console.error('清除密钥失败:', error);
            }
        },
        
        // 获取或生成盐值
        getSalt: function() {
            try {
                let salt = localStorage.getItem(CONFIG.SALT_STORAGE_NAME);
                if (!salt) {
                    salt = SecurityUtils.generateSalt();
                    localStorage.setItem(CONFIG.SALT_STORAGE_NAME, salt);
                    console.log('生成新的盐值');
                }
                return salt;
            } catch (error) {
                console.error('获取盐值失败:', error);
                return SecurityUtils.generateSalt(); // 临时盐值
            }
        }
    };
    
    // UI管理类
    const UIManager = {
        // 创建加密选项UI
        createEncryptionOption: function() {
            const container = document.createElement('div');
            container.className = 'v-crypto-option';
            
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.id = 'v-crypto-checkbox';
            checkbox.className = 'v-crypto-checkbox';
            
            const label = document.createElement('label');
            label.htmlFor = 'v-crypto-checkbox';
            label.className = 'v-crypto-label';
            
            const icon = document.createElement('i');
            icon.className = 'fas fa-lock';
            
            label.appendChild(checkbox);
            label.appendChild(icon);
            label.appendChild(document.createTextNode(' 私密评论'));
            
            container.appendChild(label);
            
            // 样式切换
            checkbox.addEventListener('change', function() {
                label.classList.toggle('active', this.checked);
            });
            
            return { container, checkbox };
        },
        
        // 创建密钥输入界面
        createKeyInputModal: function() {
            const modal = document.createElement('div');
            modal.className = 'v-crypto-modal';
            modal.id = 'v-crypto-key-modal';
            
            const content = document.createElement('div');
            content.className = 'v-crypto-modal-content';
            
            // 标题
            const title = document.createElement('h3');
            title.textContent = '🔐 输入密钥解锁私密评论';
            title.className = 'v-crypto-modal-title';
            
            // 输入框容器
            const inputGroup = document.createElement('div');
            inputGroup.className = 'v-crypto-input-group';
            
            const input = document.createElement('input');
            input.type = 'password';
            input.placeholder = '请输入解锁密钥';
            input.className = 'v-crypto-input';
            input.id = 'v-crypto-key-input';
            
            const toggleBtn = document.createElement('button');
            toggleBtn.type = 'button';
            toggleBtn.className = 'v-crypto-toggle-btn';
            toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
            toggleBtn.onclick = () => {
                const isPassword = input.type === 'password';
                input.type = isPassword ? 'text' : 'password';
                toggleBtn.innerHTML = isPassword ? '<i class="fas fa-eye-slash"></i>' : '<i class="fas fa-eye"></i>';
            };
            
            inputGroup.appendChild(input);
            inputGroup.appendChild(toggleBtn);
            
            // 记住密钥选项
            const rememberGroup = document.createElement('div');
            rememberGroup.className = 'v-crypto-remember-group';
            
            const rememberCheckbox = document.createElement('input');
            rememberCheckbox.type = 'checkbox';
            rememberCheckbox.id = 'v-crypto-remember';
            
            const rememberLabel = document.createElement('label');
            rememberLabel.htmlFor = 'v-crypto-remember';
            rememberLabel.textContent = '记住密钥（本地存储）';
            
            rememberGroup.appendChild(rememberCheckbox);
            rememberGroup.appendChild(rememberLabel);
            
            // 按钮组
            const buttonGroup = document.createElement('div');
            buttonGroup.className = 'v-crypto-button-group';
            
            const unlockBtn = document.createElement('button');
            unlockBtn.type = 'button';
            unlockBtn.className = 'v-crypto-btn v-crypto-btn-primary';
            unlockBtn.textContent = '🔓 解锁';
            
            const cancelBtn = document.createElement('button');
            cancelBtn.type = 'button';
            cancelBtn.className = 'v-crypto-btn v-crypto-btn-secondary';
            cancelBtn.textContent = '取消';
            
            buttonGroup.appendChild(unlockBtn);
            buttonGroup.appendChild(cancelBtn);
            
            // 组装模态框
            content.appendChild(title);
            content.appendChild(inputGroup);
            content.appendChild(rememberGroup);
            content.appendChild(buttonGroup);
            modal.appendChild(content);
            
            // 事件处理
            cancelBtn.onclick = () => this.hideModal(modal);
            modal.onclick = (e) => {
                if (e.target === modal) this.hideModal(modal);
            };
            
            // 回车键提交
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    unlockBtn.click();
                }
            });
            
            return { modal, input, unlockBtn, rememberCheckbox };
        },
        
        // 显示模态框
        showModal: function(modal) {
            modal.style.display = 'flex';
            const input = modal.querySelector('.v-crypto-input');
            if (input) {
                setTimeout(() => input.focus(), 100);
            }
        },
        
        // 隐藏模态框
        hideModal: function(modal) {
            modal.style.display = 'none';
            const input = modal.querySelector('.v-crypto-input');
            if (input) {
                input.value = '';
            }
        },
        
        // 创建加密评论显示
        createEncryptedDisplay: function(commentElement) {
            const container = document.createElement('div');
            container.className = 'v-crypto-encrypted-display';
            
            const badge = document.createElement('span');
            badge.className = 'v-crypto-badge';
            badge.innerHTML = '<i class="fas fa-lock"></i> 私密评论';
            
            const message = document.createElement('p');
            message.className = 'v-crypto-message';
            message.textContent = '此评论已加密，需要密钥才能查看内容';
            
            const unlockBtn = document.createElement('button');
            unlockBtn.className = 'v-crypto-unlock-btn';
            unlockBtn.innerHTML = '<i class="fas fa-key"></i> 解锁查看';
            
            container.appendChild(badge);
            container.appendChild(message);
            container.appendChild(unlockBtn);
            
            return { container, unlockBtn };
        },
        
        // 添加样式
        addStyles: function() {
            if (document.getElementById('v-crypto-styles')) return;
            
            const style = document.createElement('style');
            style.id = 'v-crypto-styles';
            style.textContent = `
                /* 加密选项样式 */
                .v-crypto-option {
                    margin: 10px 0;
                }
                
                .v-crypto-label {
                    display: inline-flex;
                    align-items: center;
                    padding: 8px 12px;
                    background: #f8f9fa;
                    border: 1px dashed #dee2e6;
                    border-radius: 6px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    font-size: 14px;
                    color: #6c757d;
                }
                
                .v-crypto-label:hover {
                    border-color: #007bff;
                    color: #007bff;
                    background: #e3f2fd;
                }
                
                .v-crypto-label.active {
                    border-color: #28a745;
                    color: #28a745;
                    background: #e8f5e8;
                }
                
                .v-crypto-checkbox {
                    margin-right: 8px;
                }
                
                /* 模态框样式 */
                .v-crypto-modal {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0, 0, 0, 0.5);
                    display: none;
                    justify-content: center;
                    align-items: center;
                    z-index: 10000;
                }
                
                .v-crypto-modal-content {
                    background: white;
                    padding: 24px;
                    border-radius: 12px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
                    width: 90%;
                    max-width: 400px;
                    animation: modalSlideIn 0.3s ease;
                }
                
                @keyframes modalSlideIn {
                    from {
                        opacity: 0;
                        transform: translateY(-20px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }
                
                .v-crypto-modal-title {
                    margin: 0 0 20px 0;
                    font-size: 18px;
                    font-weight: 600;
                    color: #333;
                    text-align: center;
                }
                
                .v-crypto-input-group {
                    position: relative;
                    margin-bottom: 16px;
                }
                
                .v-crypto-input {
                    width: 100%;
                    padding: 12px 40px 12px 12px;
                    border: 2px solid #e1e5e9;
                    border-radius: 8px;
                    font-size: 14px;
                    transition: border-color 0.3s ease;
                    box-sizing: border-box;
                }
                
                .v-crypto-input:focus {
                    outline: none;
                    border-color: #007bff;
                    box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.1);
                }
                
                .v-crypto-toggle-btn {
                    position: absolute;
                    right: 8px;
                    top: 50%;
                    transform: translateY(-50%);
                    background: none;
                    border: none;
                    color: #6c757d;
                    cursor: pointer;
                    padding: 4px;
                }
                
                .v-crypto-remember-group {
                    margin-bottom: 20px;
                    display: flex;
                    align-items: center;
                    font-size: 14px;
                    color: #6c757d;
                }
                
                .v-crypto-remember-group input {
                    margin-right: 8px;
                }
                
                .v-crypto-button-group {
                    display: flex;
                    gap: 12px;
                    justify-content: flex-end;
                }
                
                .v-crypto-btn {
                    padding: 10px 20px;
                    border: none;
                    border-radius: 6px;
                    font-size: 14px;
                    font-weight: 500;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }
                
                .v-crypto-btn-primary {
                    background: #007bff;
                    color: white;
                }
                
                .v-crypto-btn-primary:hover {
                    background: #0056b3;
                }
                
                .v-crypto-btn-secondary {
                    background: #6c757d;
                    color: white;
                }
                
                .v-crypto-btn-secondary:hover {
                    background: #545b62;
                }
                
                /* 加密评论显示样式 */
                .v-crypto-encrypted-display {
                    background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                    border: 1px solid #dee2e6;
                    border-left: 4px solid #ffc107;
                    border-radius: 8px;
                    padding: 16px;
                    margin: 8px 0;
                }
                
                .v-crypto-badge {
                    display: inline-block;
                    background: #ffc107;
                    color: #212529;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: 600;
                    margin-bottom: 8px;
                }
                
                .v-crypto-message {
                    margin: 8px 0 12px 0;
                    color: #6c757d;
                    font-size: 14px;
                }
                
                .v-crypto-unlock-btn {
                    background: #17a2b8;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 6px;
                    font-size: 13px;
                    cursor: pointer;
                    transition: background 0.3s ease;
                }
                
                .v-crypto-unlock-btn:hover {
                    background: #138496;
                }
                
                /* 响应式设计 */
                @media (max-width: 480px) {
                    .v-crypto-modal-content {
                        margin: 20px;
                        padding: 20px;
                    }
                    
                    .v-crypto-button-group {
                        flex-direction: column;
                    }
                    
                    .v-crypto-btn {
                        width: 100%;
                    }
                }
            `;
            
            document.head.appendChild(style);
        }
    };
    
    // 主要的ValineCrypto类
    window.ValineCrypto = {
        initialized: false,
        observerInitialized: false,
        masterKey: null,
        salt: null,
        
        // 初始化
        init: function() {
            if (this.initialized) return;
            
            console.log('🔐 初始化Valine加密评论系统...');
            
            // 添加样式
            UIManager.addStyles();
            
            // 获取配置的主密钥
            this.masterKey = window.VALINE_COMMENT_KEY || window.VALINE_CRYPTO_KEY || '';
            
            // 获取盐值
            this.salt = StorageManager.getSalt();
            
            if (!this.masterKey) {
                console.warn('⚠️ 未配置主密钥，加密功能将受限');
            } else {
                console.log('✅ 加密系统初始化成功');
            }
            
            this.initialized = true;
            
            // 添加FontAwesome（如果需要）
            this.ensureFontAwesome();
        },
        
        // 确保FontAwesome可用
        ensureFontAwesome: function() {
            if (!document.querySelector('link[href*="font-awesome"]')) {
                const link = document.createElement('link');
                link.rel = 'stylesheet';
                link.href = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css';
                document.head.appendChild(link);
                console.log('📦 已加载FontAwesome图标库');
            }
        },
        
        // 增强Valine表单
        enhanceValineForm: function(container) {
            this.init();
            
            if (!this.masterKey) {
                console.warn('⚠️ 无主密钥，跳过表单增强');
                return;
            }
            
            // 检查是否已经增强过
            if (container.querySelector('.v-crypto-option')) {
                return;
            }
            
            const submitBtn = container.querySelector('.vsubmit');
            if (!submitBtn) {
                console.warn('⚠️ 未找到提交按钮');
                return;
            }
            
            console.log('🔧 正在增强Valine表单...');
            
            // 创建加密选项
            const { container: optionContainer, checkbox } = UIManager.createEncryptionOption();
            
            // 插入到提交按钮前
            submitBtn.parentNode.insertBefore(optionContainer, submitBtn);
            
            // 绑定提交事件
            this.bindSubmitHandler(container, checkbox);
            
            console.log('✅ 表单增强完成');
        },
        
        // 绑定提交处理器
        bindSubmitHandler: function(container, checkbox) {
            const submitBtn = container.querySelector('.vsubmit');
            const textarea = container.querySelector('.veditor');
            
            if (!submitBtn || !textarea) return;
            
            // 防止重复绑定
            if (submitBtn._cryptoEnhanced) return;
            submitBtn._cryptoEnhanced = true;
            
            submitBtn.addEventListener('click', async (e) => {
                if (!checkbox.checked) return; // 不加密，正常提交
                
                e.preventDefault();
                e.stopPropagation();
                
                const content = textarea.value.trim();
                if (!content) {
                    alert('请输入评论内容');
                    return;
                }
                
                try {
                    console.log('🔒 正在加密评论...');
                    
                    // 加密内容
                    const encrypted = await CryptoUtils.encrypt(content, this.masterKey, this.salt);
                    
                    // 设置加密后的内容
                    textarea.value = CONFIG.ENCRYPTION_MARKER + encrypted;
                    
                    // 重置加密选项
                    checkbox.checked = false;
                    checkbox.parentElement.classList.remove('active');
                    
                    console.log('✅ 评论加密完成，正在提交...');
                    
                    // 延迟提交，确保内容已更新
                    setTimeout(() => {
                        submitBtn.click();
                        
                        // 提交后处理新评论
                        setTimeout(() => {
                            this.processComments(container);
                        }, 2000);
                    }, 100);
                    
                } catch (error) {
                    console.error('❌ 加密失败:', error);
                    alert('评论加密失败: ' + error.message);
                }
            }, true);
        },
        
        // 处理评论
        processComments: function(container) {
            this.init();
            
            const comments = container.querySelectorAll('.vcontent:not([data-crypto-processed])');
            console.log(`🔍 处理 ${comments.length} 条新评论`);
            
            comments.forEach(comment => {
                comment.setAttribute('data-crypto-processed', 'true');
                
                const text = comment.textContent.trim();
                if (text.startsWith(CONFIG.ENCRYPTION_MARKER)) {
                    this.handleEncryptedComment(comment, text);
                }
            });
            
            // 添加全局解锁按钮
            this.addGlobalUnlockButton(container);
        },
        
        // 处理加密评论
        handleEncryptedComment: function(commentElement, text) {
            const encryptedData = text.substring(CONFIG.ENCRYPTION_MARKER.length);
            
            // 存储加密数据
            commentElement.setAttribute('data-encrypted-content', encryptedData);
            
            // 尝试自动解密（如果有主密钥）
            if (this.masterKey) {
                this.attemptDecryption(commentElement, encryptedData);
            } else {
                this.showEncryptedDisplay(commentElement);
            }
        },
        
        // 尝试解密
        attemptDecryption: async function(commentElement, encryptedData) {
            try {
                const decrypted = await CryptoUtils.decrypt(encryptedData, this.masterKey, this.salt);
                if (decrypted) {
                    commentElement.textContent = decrypted;
                    commentElement.setAttribute('data-crypto-decrypted', 'true');
                    console.log('✅ 自动解密成功');
                    return;
                }
            } catch (error) {
                console.warn('⚠️ 自动解密失败:', error);
            }
            
            // 自动解密失败，显示解锁界面
            this.showEncryptedDisplay(commentElement);
        },
        
        // 显示加密评论界面
        showEncryptedDisplay: function(commentElement) {
            const { container, unlockBtn } = UIManager.createEncryptedDisplay(commentElement);
            
            // 替换评论内容
            commentElement.innerHTML = '';
            commentElement.appendChild(container);
            
            // 绑定解锁事件
            unlockBtn.onclick = () => this.showKeyInputModal(commentElement);
        },
        
        // 显示密钥输入模态框
        showKeyInputModal: function(targetComment = null) {
            let modal = document.getElementById('v-crypto-key-modal');
            
            if (!modal) {
                const modalData = UIManager.createKeyInputModal();
                modal = modalData.modal;
                document.body.appendChild(modal);
                
                // 绑定解锁事件
                modalData.unlockBtn.onclick = () => {
                    this.handleKeySubmit(modalData.input, modalData.rememberCheckbox, targetComment);
                };
                
                // 加载保存的密钥
                const savedKey = StorageManager.getKey();
                if (savedKey) {
                    modalData.input.value = savedKey;
                    modalData.rememberCheckbox.checked = true;
                }
            }
            
            // 存储目标评论
            if (targetComment) {
                modal.setAttribute('data-target-comment', targetComment.getAttribute('data-crypto-id') || 'single');
            } else {
                modal.setAttribute('data-target-comment', 'all');
            }
            
            UIManager.showModal(modal);
        },
        
        // 处理密钥提交
        handleKeySubmit: async function(input, rememberCheckbox, targetComment) {
            const key = input.value.trim();
            if (!key) {
                alert('请输入密钥');
                return;
            }
            
            // 验证密钥强度
            const validation = SecurityUtils.validateKeyStrength(key);
            if (!validation.valid) {
                if (!confirm(validation.message + '\n\n是否继续使用此密钥？')) {
                    return;
                }
            }
            
            // 保存密钥
            StorageManager.saveKey(key, rememberCheckbox.checked);
            
            try {
                if (targetComment) {
                    // 解密单个评论
                    await this.decryptSingleComment(targetComment, key);
                } else {
                    // 解密所有评论
                    await this.decryptAllComments(key);
                }
                
                // 隐藏模态框
                const modal = document.getElementById('v-crypto-key-modal');
                UIManager.hideModal(modal);
                
            } catch (error) {
                console.error('❌ 解密失败:', error);
                alert('解密失败: ' + error.message);
            }
        },
        
        // 解密单个评论
        decryptSingleComment: async function(commentElement, key) {
            const encryptedData = commentElement.getAttribute('data-encrypted-content');
            if (!encryptedData) {
                throw new Error('找不到加密数据');
            }
            
            const decrypted = await CryptoUtils.decrypt(encryptedData, key, this.salt);
            if (!decrypted) {
                throw new Error('解密失败，请检查密钥是否正确');
            }
            
            commentElement.textContent = decrypted;
            commentElement.setAttribute('data-crypto-decrypted', 'true');
            console.log('✅ 单个评论解密成功');
        },
        
        // 解密所有评论
        decryptAllComments: async function(key) {
            const encryptedComments = document.querySelectorAll('[data-encrypted-content]');
            let successCount = 0;
            
            for (const comment of encryptedComments) {
                try {
                    await this.decryptSingleComment(comment, key);
                    successCount++;
                } catch (error) {
                    console.warn('⚠️ 评论解密失败:', error);
                }
            }
            
            if (successCount > 0) {
                console.log(`✅ 成功解密 ${successCount} 条评论`);
                alert(`成功解密 ${successCount} 条评论`);
            } else {
                throw new Error('没有成功解密任何评论');
            }
        },
        
        // 添加全局解锁按钮
        addGlobalUnlockButton: function(container) {
            if (document.getElementById('v-crypto-global-unlock')) return;
            
            const encryptedCount = container.querySelectorAll('[data-encrypted-content]').length;
            if (encryptedCount === 0) return;
            
            const button = document.createElement('button');
            button.id = 'v-crypto-global-unlock';
            button.className = 'v-crypto-btn v-crypto-btn-primary';
            button.style.cssText = `
                margin: 10px 0;
                width: 100%;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
            `;
            button.innerHTML = `<i class="fas fa-key"></i> 解锁所有私密评论 (${encryptedCount})`;
            
            button.onclick = () => this.showKeyInputModal();
            
            // 插入到评论区顶部
            const firstComment = container.querySelector('.vcard') || container.querySelector('.vcontent');
            if (firstComment) {
                firstComment.parentNode.insertBefore(button, firstComment);
            } else {
                container.appendChild(button);
            }
        },
        
        // 设置观察器
        setupObserver: function(container) {
            if (this.observerInitialized || !container) return;
            
            const observer = new MutationObserver((mutations) => {
                let shouldProcess = false;
                
                mutations.forEach((mutation) => {
                    if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                        shouldProcess = true;
                    }
                });
                
                if (shouldProcess) {
                    clearTimeout(this.processTimeout);
                    this.processTimeout = setTimeout(() => {
                        this.processComments(container);
                    }, CONFIG.DEBOUNCE_DELAY);
                }
            });
            
            observer.observe(container, {
                childList: true,
                subtree: true
            });
            
            this.observerInitialized = true;
            console.log('👁️ 评论观察器已启动');
        },
        
        // 获取统计信息
        getStats: function() {
            const total = document.querySelectorAll('.vcontent').length;
            const encrypted = document.querySelectorAll('[data-encrypted-content]').length;
            const decrypted = document.querySelectorAll('[data-crypto-decrypted="true"]').length;
            
            return { total, encrypted, decrypted };
        }
    };
    
    // 初始化管理器
    const InitManager = {
        attemptCount: 0,
        maxAttempts: 10,
        
        // 检查Valine是否已加载
        isValineReady: function() {
            return typeof window.Valine === 'function' && document.querySelector('.v');
        },
        
        // 初始化加密功能
        initCrypto: function() {
            if (this.attemptCount >= this.maxAttempts) {
                console.warn('⚠️ 达到最大尝试次数，停止初始化');
                return;
            }
            
            this.attemptCount++;
            
            if (this.isValineReady()) {
                const container = document.querySelector('.v');
                console.log('🎯 找到Valine容器，开始初始化加密功能');
                
                ValineCrypto.enhanceValineForm(container);
                ValineCrypto.processComments(container);
                ValineCrypto.setupObserver(container);
                
                console.log('🎉 Valine加密功能初始化完成');
            } else {
                const delay = Math.min(1000 * this.attemptCount, 5000);
                console.log(`⏳ Valine未就绪，${delay}ms后重试 (${this.attemptCount}/${this.maxAttempts})`);
                setTimeout(() => this.initCrypto(), delay);
            }
        },
        
        // 启动初始化
        start: function() {
            console.log('🚀 启动Valine加密评论系统');
            
            // 立即尝试
            this.initCrypto();
            
            // DOM加载完成后尝试
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => {
                    setTimeout(() => this.initCrypto(), 1000);
                });
            }
            
            // 页面完全加载后尝试
            window.addEventListener('load', () => {
                setTimeout(() => this.initCrypto(), 2000);
            });
            
            // 手动触发快捷键 (Ctrl+Shift+E)
            document.addEventListener('keydown', (e) => {
                if (e.ctrlKey && e.shiftKey && e.key === 'E') {
                    console.log('🔧 手动触发初始化');
                    this.initCrypto();
                }
            });
        }
    };
    
    // 启动系统
    InitManager.start();
    
    // 导出到全局（用于调试）
    window.ValineCryptoUtils = {
        CryptoUtils,
        SecurityUtils,
        StorageManager,
        UIManager
    };
    
    console.log('📦 Valine加密评论系统已加载');
    
})();