
function generate() {
    const domain = document.getElementById('domain').value.trim().replace(/^https?:\/\//,'').replace(/\/.*$/,'');
    const mode = document.querySelector('input[name=mode]:checked').value;
    const mxRaw = document.getElementById('mxList').value.trim();
    const maxAge = parseInt(document.getElementById('maxAge').value) || 86400;
    const v = document.getElementById('validation');

    const warnings = [];
    if (!domain) {
        v.className = 'validation warn';
        v.style.display = 'block';
        v.innerHTML = '❌ 请填写域名';
        return;
    }
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(domain)) {
        warnings.push('域名格式可能不正确（应为 example.com 形式）');
    }

    const mxs = mxRaw.split('\n').map(s => s.trim().replace(/^\./,'')).filter(Boolean);
    if (mxs.length === 0) {
        warnings.push('未填写 MX 主机列表，策略文件将为空（需手动补充）');
    }

    const id = Math.floor(Date.now() / 1000);
    const txtRecord = `v=STSv1; id=${id}`;

    // 策略文件
    const policyLines = ['version: STSv1', 'mode: ' + mode];
    if (mxs.length) {
        policyLines.push('mx: ' + mxs.join('\nmx: '));
    }
    policyLines.push('max_age: ' + maxAge);
    const policy = policyLines.join('\n');

    v.className = 'validation warn';
    v.style.display = 'block';
    v.innerHTML = '⚠️ ' + (warnings.length ? warnings.join('<br>⚠️ ') : '配置已生成，请按下方部署清单逐项发布。');

    const out1 = document.getElementById('output');
    out1.style.display = 'block';
    out1.innerHTML = `<button class="copy-btn" onclick="copyRec(this)">复制</button><strong>① DNS TXT 记录</strong>（主机名：<code>_mta-sts.${domain}</code>）<br><br>${txtRecord}`;

    const out2 = document.getElementById('output2');
    out2.style.display = 'block';
    out2.innerHTML = `<button class="copy-btn" onclick="copyRec(this)">复制</button><strong>② 策略文件内容</strong>（部署到 <code>https://mta-sts.${domain}/.well-known/mta-sts.txt</code>，Content-Type: text/plain）<br><br>${policy}`;
}

function copyRec(btn) {
    const node = btn.parentNode.cloneNode(true);
    node.querySelector('.copy-btn').remove();
    const text = node.innerText.trim();
    navigator.clipboard.writeText(text).then(() => {
        btn.textContent = '已复制 ✓';
        setTimeout(() => btn.textContent = '复制', 1500);
    });
}
