/**
 * Valine 评论加密扩展
 * 为Valine添加评论加密/解密功能
 */

(function() {
  // 辅助函数：转换 buffer 和 base64
  function bufferToBase64(buffer) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
  }
  
  function base64ToBuffer(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  }
  
  // 密钥派生函数
  async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits", "deriveKey"]
    );
    
    return window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: typeof salt === 'string' ? encoder.encode(salt) : salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
  
  // 加密函数
  async function encryptComment(comment, password) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt);
    const encoder = new TextEncoder();
    
    const encryptedContent = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoder.encode(comment)
    );
    
    // 将IV和salt与密文一起存储
    return {
      encryptedData: bufferToBase64(encryptedContent),
      iv: bufferToBase64(iv),
      salt: bufferToBase64(salt)
    };
  }
  
  // 解密函数
  async function decryptComment(encryptedComment, password) {
    try {
      const iv = base64ToBuffer(encryptedComment.iv);
      const salt = base64ToBuffer(encryptedComment.salt);
      const encryptedData = base64ToBuffer(encryptedComment.encryptedData);
      const key = await deriveKey(password, salt);
      
      const decryptedContent = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        encryptedData
      );
      
      return new TextDecoder().decode(decryptedContent);
    } catch (e) {
      console.error("解密失败，密码错误或数据已损坏", e);
      return null;
    }
  }

  // 扩展Valine原型
  function extendValine() {
    if (typeof Valine !== 'function') {
      console.error('Valine not found. Make sure Valine is loaded before this script.');
      return;
    }
    
    // 保存原始初始化方法
    const originalInit = Valine.prototype.init;
    
    // 扩展初始化方法
    Valine.prototype.init = function() {
      // 调用原始初始化
      originalInit.call(this);
      
      // 检查是否启用加密
      if (this.config.enableEncryption) {
        this.initEncryption();
      }
      
      return this;
    };
    
    // 添加加密初始化方法
    Valine.prototype.initEncryption = function() {
      const self = this;
      const el = this.el;
      
      // 默认配置
      this.config.encryptionPrompt = this.config.encryptionPrompt || '此评论已加密，请输入密码查看';
      
      // 添加样式
      const style = document.createElement('style');
      style.innerHTML = `
        .vencrypt-container {
          margin: 10px 0;
          padding: 8px;
          border-radius: 6px;
          background-color: #f8f8f8;
        }
        .vencrypt-toggle {
          display: flex;
          align-items: center;
        }
        .vencrypt-toggle input {
          margin-right: 5px;
        }
        .vencrypt-password {
          margin-top: 8px;
        }
        .vencrypt-password input {
          width: 100%;
          padding: 6px 8px;
          border: 1px solid #ddd;
          border-radius: 3px;
        }
        .vencrypted-comment {
          padding: 10px;
          background-color: #f0f0f0;
          border-radius: 6px;
          margin: 5px 0;
        }
        .vencrypted-tip {
          color: #888;
          font-style: italic;
          margin: 0 0 10px 0;
        }
        .vencrypted-form {
          display: flex;
        }
        .vencrypted-password {
          flex: 1;
          padding: 6px 8px;
          border: 1px solid #ddd;
          border-radius: 3px 0 0 3px;
        }
        .vencrypted-submit {
          border: 1px solid #ddd;
          border-left: none;
          background-color: #f0f0f0;
          padding: 6px 12px;
          border-radius: 0 3px 3px 0;
          cursor: pointer;
        }
        .vencrypted-submit:hover {
          background-color: #e0e0e0;
        }
        .vdecrypted-content {
          margin-top: 10px;
          padding: 10px;
          background-color: #f9f9f9;
          border-radius: 6px;
          border-left: 3px solid #42b983;
        }
      `;
      document.head.appendChild(style);
      
      // 添加加密选项到评论表单
      const postEl = el.querySelector('.vpost');
      if (!postEl) return this;
      
      const encryptContainer = document.createElement('div');
      encryptContainer.className = 'vencrypt-container';
      encryptContainer.innerHTML = `
        <div class="vencrypt-toggle">
          <input type="checkbox" id="vencrypt-enable" />
          <label for="vencrypt-enable">加密此评论</label>
        </div>
        <div class="vencrypt-password" style="display:none;">
          <input type="password" id="vencrypt-password" placeholder="输入加密密码" />
        </div>
      `;
      
      // 将加密选项添加到表单
      postEl.insertBefore(encryptContainer, el.querySelector('.vcontrol'));
      
      // 处理加密复选框事件
      const encryptToggle = el.querySelector('#vencrypt-enable');
      const passwordField = el.querySelector('.vencrypt-password');
      encryptToggle.addEventListener('change', function() {
        passwordField.style.display = this.checked ? 'block' : 'none';
      });
      
      // 修改提交处理逻辑
      const submitBtn = el.querySelector('.vsubmit');
      submitBtn.addEventListener('click', async function(e) {
        if (!encryptToggle.checked) return; // 未启用加密，使用原始流程
        
        // 阻止默认提交
        e.preventDefault();
        e.stopPropagation();
        
        const password = el.querySelector('#vencrypt-password').value;
        if (!password) {
          self.alert.show({
            type: 0,
            text: '请输入加密密码！',
          });
          return;
        }
        
        // 获取评论内容
        const commentInput = el.querySelector('.veditor');
        const commentContent = commentInput.value;
        if (!commentContent) return;
        
        try {
          // 加密评论
          const encryptedData = await encryptComment(commentContent, password);
          
          // 准备评论数据
          const commentData = {
            nick: el.querySelector('.vnick').value,
            mail: el.querySelector('.vmail').value,
            link: el.querySelector('.vlink').value,
            comment: '[加密评论]', // 明文字段用占位符
            url: window.location.pathname,
            isEncrypted: true,
            encryptedData: encryptedData.encryptedData,
            iv: encryptedData.iv,
            salt: encryptedData.salt
          };
          
          // 创建评论对象
          const Comment = AV.Object.extend('Comment');
          const comment = new Comment();
          
          // 设置评论字段
          for (let key in commentData) {
            comment.set(key, commentData[key]);
          }
          
          // 显示提交中状态
          submitBtn.setAttribute('disabled', true);
          submitBtn.textContent = '提交中...';
          
          // 保存到LeanCloud
          comment.save().then(function() {
            // 成功提交
            self.alert.show({
              type: 1,
              text: '评论提交成功',
            });
            
            // 清空表单
            el.querySelector('.veditor').value = '';
            encryptToggle.checked = false;
            passwordField.style.display = 'none';
            el.querySelector('#vencrypt-password').value = '';
            
            // 恢复提交按钮
            submitBtn.removeAttribute('disabled');
            submitBtn.textContent = '提交';
            
            // 刷新评论列表
            self.bind();
          }).catch(function(error) {
            // 提交失败
            self.alert.show({
              type: 0,
              text: '评论提交失败: ' + error.message,
            });
            
            // 恢复提交按钮
            submitBtn.removeAttribute('disabled');
            submitBtn.textContent = '提交';
          });
        } catch (error) {
          console.error('加密失败', error);
          self.alert.show({
            type: 0,
            text: '评论加密失败: ' + error.message,
          });
        }
      });
      
      // 扩展评论渲染函数
      const originalRender = self.renderComments;
      self.renderComments = function(comments) {
        // 调用原始渲染函数
        originalRender.call(this, comments);
        
        // 处理已渲染的加密评论
        comments.forEach(comment => {
          if (comment.get('isEncrypted')) {
            const commentId = comment.id;
            const commentEl = this.el.querySelector(`#${commentId}`);
            if (!commentEl) return;
            
            const contentEl = commentEl.querySelector('.vcontent');
            if (!contentEl) return;
            
            // 替换内容为解密表单
            contentEl.innerHTML = `
              <div class="vencrypted-comment" data-comment-id="${commentId}">
                <p class="vencrypted-tip">${this.config.encryptionPrompt}</p>
                <div class="vencrypted-form">
                  <input type="password" class="vencrypted-password" placeholder="输入密码解锁" />
                  <button class="vencrypted-submit">解锁</button>
                </div>
                <div class="vdecrypted-content" style="display:none;"></div>
              </div>
            `;
            
            // 绑定解密事件
            const decryptBtn = contentEl.querySelector('.vencrypted-submit');
            const passwordInput = contentEl.querySelector('.vencrypted-password');
            const decryptedContent = contentEl.querySelector('.vdecrypted-content');
            
            decryptBtn.addEventListener('click', async function() {
              const password = passwordInput.value;
              if (!password) {
                alert('请输入密码');
                return;
              }
              
              // 解密尝试
              try {
                const encryptedData = {
                  encryptedData: comment.get('encryptedData'),
                  iv: comment.get('iv'),
                  salt: comment.get('salt')
                };
                
                decryptBtn.textContent = '解密中...';
                decryptBtn.disabled = true;
                
                const decryptedText = await decryptComment(encryptedData, password);
                if (decryptedText) {
                  // 解密成功
                  decryptedContent.innerHTML = marked.parse(decryptedText);
                  decryptedContent.style.display = 'block';
                  passwordInput.style.display = 'none';
                  decryptBtn.style.display = 'none';
                  contentEl.querySelector('.vencrypted-tip').textContent = '已解密的评论:';
                } else {
                  alert('密码错误或数据已损坏');
                  decryptBtn.textContent = '解锁';
                  decryptBtn.disabled = false;
                }
              } catch (error) {
                console.error('解密失败', error);
                alert('解密失败: ' + error.message);
                decryptBtn.textContent = '解锁';
                decryptBtn.disabled = false;
              }
            });
          }
        });
      };
      
      return this;
    };
  }
  
  // 导出工具函数
  window.ValineEncryption = {
    encrypt: encryptComment,
    decrypt: decryptComment,
    extend: extendValine
  };
  
  // 自动扩展Valine（如果已加载）
  if (typeof Valine === 'function') {
    extendValine();
  } else {
    // 监听Valine加载
    const originalValine = window.Valine;
    Object.defineProperty(window, 'Valine', {
      get: function() {
        return originalValine;
      },
      set: function(newValine) {
        originalValine = newValine;
        if (typeof newValine === 'function') {
          extendValine();
        }
      },
      configurable: true
    });
  }
})(); 