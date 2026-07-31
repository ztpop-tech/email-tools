
async function generate() {
    const selector = document.getElementById('selector').value.trim() || 'default';
    const bits = parseInt(document.querySelector('input[name=bits]:checked').value);
    const hash = document.querySelector('input[name=hash]:checked').value;
    const v = document.getElementById('validation');

    v.className = 'validation warn';
    v.style.display = 'block';
    v.innerHTML = '⏳ 正在本地生成 RSA ' + bits + ' 密钥对（约 1-3 秒）...';

    try {
        const keyPair = await crypto.subtle.generateKey(
            { name: 'RSASSA-PKCS1-v1_5', modulusLength: bits, publicExponent: new Uint8Array([1,0,1]), hash: hash === 'rsa-sha1' ? 'SHA-1' : 'SHA-256' },
            true,
            ['sign', 'verify']
        );

        // 导出 PEM
        const privRaw = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const pubRaw = await crypto.subtle.exportKey('spki', keyPair.publicKey);

        function toPEM(buf, type) {
            const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
            const lines = b64.match(/.{1,64}/g).join('\n');
            return `-----BEGIN ${type} KEY-----\n${lines}\n-----END ${type} KEY-----`;
        }
        const privPem = toPEM(privRaw, 'PRIVATE');
        const pubPem = toPEM(pubRaw, 'PUBLIC');

        // 提取公钥 Base64（去掉 PEM 头尾与换行）用于 TXT
        const pubB64 = pubPem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, '');

        const record = `v=DKIM1; k=rsa; p=${pubB64}`;

        v.className = 'validation ok';
        v.style.display = 'block';
        v.innerHTML = `✅ 密钥对已生成（RSA ${bits} / ${hash}）。请将私钥配置到邮件服务器，公钥发布到 DNS 主机名 <code>${selector}._domainkey.您的域名</code>。`;

        const out1 = document.getElementById('output');
        out1.style.display = 'block';
        out1.innerHTML = `<button class="copy-btn" onclick="copyRec(this)">复制</button><strong>📄 DNS TXT 记录</strong>（主机名：${selector}._domainkey.您的域名）<br><br>${record}`;

        const out2 = document.getElementById('output2');
        out2.style.display = 'block';
        out2.innerHTML = `<button class="copy-btn" onclick="copyRec(this)">复制</button><strong>🔑 私钥（配置到邮件服务器，勿公开！）</strong><br><br>${privPem}`;

        const out3 = document.getElementById('output3');
        out3.style.display = 'block';
        out3.innerHTML = `<button class="copy-btn" onclick="copyRec(this)">复制</button><strong>🔓 公钥 PEM（备用格式）</strong><br><br>${pubPem}`;
    } catch (e) {
        v.className = 'validation warn';
        v.style.display = 'block';
        v.innerHTML = '❌ 生成失败（可能浏览器不支持 Web Crypto）：' + e.message;
    }
}

function copyRec(btn) {
    // 只复制代码部分（去掉按钮文字）
    const node = btn.parentNode.cloneNode(true);
    node.querySelector('.copy-btn').remove();
    const text = node.innerText.trim();
    navigator.clipboard.writeText(text).then(() => {
        btn.textContent = '已复制 ✓';
        setTimeout(() => btn.textContent = '复制', 1500);
    });
}
