/**
 * Valine Crypto Configuration
 * 加密评论系统配置文件
 * 
 * 使用说明:
 * 1. 设置 VALINE_CRYPTO_KEY 为你的主密钥
 * 2. 根据需要调整其他配置项
 * 3. 在 Valine 初始化前加载此配置
 */

(function() {
    'use strict';
    
    // ===========================================
    // 主要配置 - 请根据需要修改
    // ===========================================
    
    /**
     * 主密钥配置
     * 重要: 请设置一个强密钥，建议包含大小写字母、数字和特殊字符
     * 长度至少8位，推荐16位以上
     */
    window.VALINE_CRYPTO_KEY = 'bJUi6PNTzdmeXYJ8KzHw5vL7qEC2F9Dx';
    
    /**
     * 加密配置
     */
    window.VALINE_CRYPTO_CONFIG = {
        // 是否启用加密功能
        enabled: true,
        
        // 是否自动解密（博主模式）
        autoDecrypt: true,
        
        // 是否允许访客解锁评论
        allowGuestUnlock: true,
        
        // 密钥强度要求
        keyStrength: {
            minLength: 8,
            requireMixed: true, // 要求包含多种字符类型
            showWarning: true   // 显示弱密钥警告
        },
        
        // UI配置
        ui: {
            // 加密选项文本
            encryptOptionText: '🔒 私密评论',
            
            // 加密评论显示文本
            encryptedBadgeText: '🔒 私密评论',
            encryptedMessageText: '此评论已加密，需要密钥才能查看内容',
            unlockButtonText: '🔓 解锁查看',
            
            // 模态框文本
            modalTitle: '🔐 输入密钥解锁私密评论',
            inputPlaceholder: '请输入解锁密钥',
            rememberKeyText: '记住密钥（本地存储）',
            unlockAllButtonText: '解锁所有私密评论',
            
            // 主题色彩
            primaryColor: '#007bff',
            warningColor: '#ffc107',
            successColor: '#28a745',
            dangerColor: '#dc3545'
        },
        
        // 安全配置
        security: {
            // 盐值长度
            saltLength: 16,
            
            // PBKDF2 迭代次数
            pbkdf2Iterations: 100000,
            
            // 是否启用本地密钥存储
            allowKeyStorage: true,
            
            // 密钥存储过期时间（毫秒，0表示永不过期）
            keyStorageExpiry: 0,
            
            // 是否在控制台显示调试信息
            debugMode: false
        },
        
        // 性能配置
        performance: {
            // 处理评论的防抖延迟（毫秒）
            debounceDelay: 500,
            
            // 初始化最大尝试次数
            maxInitAttempts: 10,
            
            // 初始化超时时间（毫秒）
            initTimeout: 5000
        }
    };
    
    // ===========================================
    // 高级配置 - 一般不需要修改
    // ===========================================
    
    /**
     * 加密算法配置
     */
    window.VALINE_CRYPTO_ALGORITHMS = {
        // 主加密算法
        primary: {
            name: 'AES-GCM',
            keyLength: 256,
            ivLength: 12
        },
        
        // 备用加密算法
        fallback: {
            name: 'Enhanced-XOR',
            rounds: 3,
            keyMixing: true
        },
        
        // 密钥派生
        keyDerivation: {
            algorithm: 'PBKDF2',
            hash: 'SHA-256',
            iterations: 100000
        }
    };
    
    /**
     * 存储配置
     */
    window.VALINE_CRYPTO_STORAGE = {
        // 存储键名前缀
        prefix: 'valine_crypto_',
        
        // 存储项
        keys: {
            masterKey: 'master_key',
            salt: 'salt',
            settings: 'settings'
        },
        
        // 是否启用存储加密
        encrypt: true,
        
        // 存储版本（用于迁移）
        version: '1.0.0'
    };
    
    // ===========================================
    // 环境检测和兼容性
    // ===========================================
    
    /**
     * 检测浏览器兼容性
     */
    function checkCompatibility() {
        const features = {
            crypto: !!window.crypto && !!window.crypto.subtle,
            localStorage: !!window.localStorage,
            textEncoder: !!window.TextEncoder,
            textDecoder: !!window.TextDecoder,
            mutationObserver: !!window.MutationObserver
        };
        
        const missing = Object.keys(features).filter(key => !features[key]);
        
        if (missing.length > 0) {
            console.warn('⚠️ Valine Crypto: 缺少以下浏览器特性:', missing);
            
            if (!features.crypto) {
                console.error('❌ Web Crypto API 不可用，加密功能将无法正常工作');
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 初始化配置
     */
    function initConfig() {
        // 检查兼容性
        if (!checkCompatibility()) {
            window.VALINE_CRYPTO_CONFIG.enabled = false;
            return;
        }
        
        // 验证主密钥
        if (!window.VALINE_CRYPTO_KEY || window.VALINE_CRYPTO_KEY === 'YourSecretKey2024!@#') {
            console.warn('⚠️ 请设置有效的主密钥 (VALINE_CRYPTO_KEY)');
            
            if (window.VALINE_CRYPTO_CONFIG.security.debugMode) {
                console.log('💡 提示: 在配置文件中设置 window.VALINE_CRYPTO_KEY');
            }
        }
        
        // 设置调试模式
        if (window.VALINE_CRYPTO_CONFIG.security.debugMode) {
            console.log('🔧 Valine Crypto 调试模式已启用');
            console.log('📋 当前配置:', window.VALINE_CRYPTO_CONFIG);
        }
        
        // 兼容旧版本配置
        if (window.VALINE_COMMENT_KEY && !window.VALINE_CRYPTO_KEY) {
            window.VALINE_CRYPTO_KEY = window.VALINE_COMMENT_KEY;
            console.log('🔄 已从旧版本配置迁移密钥');
        }
    }
    
    // ===========================================
    // 工具函数
    // ===========================================
    
    /**
     * 获取配置值
     */
    window.getValineCryptoConfig = function(path, defaultValue) {
        const keys = path.split('.');
        let value = window.VALINE_CRYPTO_CONFIG;
        
        for (const key of keys) {
            if (value && typeof value === 'object' && key in value) {
                value = value[key];
            } else {
                return defaultValue;
            }
        }
        
        return value;
    };
    
    /**
     * 设置配置值
     */
    window.setValineCryptoConfig = function(path, value) {
        const keys = path.split('.');
        const lastKey = keys.pop();
        let target = window.VALINE_CRYPTO_CONFIG;
        
        for (const key of keys) {
            if (!target[key] || typeof target[key] !== 'object') {
                target[key] = {};
            }
            target = target[key];
        }
        
        target[lastKey] = value;
    };
    
    /**
     * 重置配置为默认值
     */
    window.resetValineCryptoConfig = function() {
        // 保存当前密钥
        const currentKey = window.VALINE_CRYPTO_KEY;
        
        // 重新加载配置
        initConfig();
        
        // 恢复密钥
        window.VALINE_CRYPTO_KEY = currentKey;
        
        console.log('🔄 配置已重置为默认值');
    };
    
    // ===========================================
    // 配置预设
    // ===========================================
    
    /**
     * 博主模式配置
     */
    window.VALINE_CRYPTO_PRESETS = {
        // 博主模式 - 自动解密所有评论
        blogger: {
            autoDecrypt: true,
            allowGuestUnlock: false,
            security: {
                debugMode: false,
                allowKeyStorage: false
            }
        },
        
        // 访客模式 - 需要手动解锁
        guest: {
            autoDecrypt: false,
            allowGuestUnlock: true,
            security: {
                debugMode: false,
                allowKeyStorage: true
            }
        },
        
        // 开发模式 - 启用调试
        development: {
            autoDecrypt: true,
            allowGuestUnlock: true,
            security: {
                debugMode: true,
                allowKeyStorage: true
            }
        },
        
        // 生产模式 - 最佳安全性
        production: {
            autoDecrypt: false,
            allowGuestUnlock: true,
            security: {
                debugMode: false,
                allowKeyStorage: false,
                keyStorageExpiry: 24 * 60 * 60 * 1000 // 24小时
            }
        }
    };
    
    /**
     * 应用预设配置
     */
    window.applyValineCryptoPreset = function(presetName) {
        const preset = window.VALINE_CRYPTO_PRESETS[presetName];
        if (!preset) {
            console.error('❌ 未知的预设配置:', presetName);
            return false;
        }
        
        // 深度合并配置
        function deepMerge(target, source) {
            for (const key in source) {
                if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
                    if (!target[key]) target[key] = {};
                    deepMerge(target[key], source[key]);
                } else {
                    target[key] = source[key];
                }
            }
        }
        
        deepMerge(window.VALINE_CRYPTO_CONFIG, preset);
        
        console.log(`✅ 已应用预设配置: ${presetName}`);
        return true;
    };
    
    // ===========================================
    // 初始化
    // ===========================================
    
    // 立即初始化配置
    initConfig();
    
    // 在控制台显示加载信息
    console.log('📦 Valine Crypto 配置已加载');
    
    // 如果是开发环境，显示帮助信息
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        console.log('💡 开发环境检测到，可用的配置函数:');
        console.log('   - getValineCryptoConfig(path, defaultValue)');
        console.log('   - setValineCryptoConfig(path, value)');
        console.log('   - applyValineCryptoPreset(presetName)');
        console.log('   - resetValineCryptoConfig()');
        console.log('💡 可用的预设: blogger, guest, development, production');
    }
    
})();

// 自动应用预设配置
if (typeof applyValineCryptoPreset === 'function') {
  applyValineCryptoPreset('blogger');
}