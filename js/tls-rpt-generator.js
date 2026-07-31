
function generate() {
    const rua = document.getElementById('rua').value.trim();
    const ruaExtra = document.getElementById('ruaExtra').value.trim();
    const scope = document.querySelector('input[name=scope]:checked').value;
    const v = document.getElementById('validation');

    if (!rua) {
        v.className = 'validation warn';
        v.style.display = 'block';
        v.innerHTML = '❌ 请填写报告接收地址（rua）';
        return;
    }
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(rua)) {
        v.className = 'validation warn';
        v.style.display = 'block';
        v.innerHTML = '❌ 邮箱格式不正确: ' + rua;
        return;
    }

    const ruaList = ['mailto:' + rua];
    if (ruaExtra) {
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(ruaExtra)) {
            v.className = 'validation warn';
            v.style.display = 'block';
            v.innerHTML = '❌ 附加邮箱格式不正确: ' + ruaExtra;
            return;
        }
        ruaList.push('mailto:' + ruaExtra);
    }

    const record = 'v=TLSRPTv1; rua=' + ruaList.join(',');

    v.className = 'validation ok';
    v.style.display = 'block';
    v.innerHTML = '✅ 记录已生成' + (scope === 'full' ? '（适用于主域及所有子域）' : '（仅主域）') + '。发布后建议同时配置 MTA-STS。';

    const out = document.getElementById('output');
    out.style.display = 'block';
    out.innerHTML = `<button class="copy-btn" onclick="copyRec(this)">复制</button><strong>TLS-RPT TXT 记录</strong>（主机名：_smtp._tls.您的域名）<br><br>${record}`;
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
