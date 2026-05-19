const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');

dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));

dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) analyzeFile(file);
});

fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) analyzeFile(fileInput.files[0]);
});

async function analyzeFile(file) {
    document.getElementById('loading').style.display = 'block';
    document.getElementById('results').style.display = 'none';
    dropZone.style.display = 'none';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch('/analyze', { method: 'POST', body: formData });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Error en el servidor');
        }
        const data = await res.json();
        renderResults(data);
    } catch (err) {
        alert('Error: ' + err.message);
        dropZone.style.display = 'block';
    } finally {
        document.getElementById('loading').style.display = 'none';
    }
}

function renderResults(data) {
    document.getElementById('statTotal').textContent = data.total_lines;
    document.getElementById('statSuspicious').textContent = data.suspicious_lines;
    document.getElementById('statAlerts').textContent = data.alerts.length;

    const rate = data.total_lines > 0
        ? ((data.suspicious_lines / data.total_lines) * 100).toFixed(1) + '%'
        : '0%';
    document.getElementById('statRate').textContent = rate;

    document.getElementById('logTypeBadge').textContent = 'Tipo detectado: ' + data.log_type.toUpperCase();
    document.getElementById('summaryBox').textContent = data.summary;

    const list = document.getElementById('alertsList');
    list.innerHTML = '';

    if (data.alerts.length === 0) {
        list.innerHTML = '<div class="no-alerts">No se detectaron amenazas. Los logs parecen limpios.</div>';
    } else {
        data.alerts.forEach(alert => {
            list.innerHTML += `
                <div class="alert-card">
                    <div class="alert-header">
                        <span class="badge ${alert.severity}">${alert.severity}</span>
                        <span class="alert-title">${alert.title}</span>
                    </div>
                    <div class="alert-desc">${alert.description}</div>
                    <div class="recommendation">${alert.recommendation}</div>
                </div>`;
        });
    }

    document.getElementById('results').style.display = 'block';

    // botón para analizar otro archivo
    const btn = document.createElement('button');
    btn.className = 'btn';
    btn.textContent = 'Analizar otro archivo';
    btn.style.marginTop = '2rem';
    btn.onclick = () => {
        document.getElementById('results').style.display = 'none';
        dropZone.style.display = 'block';
        fileInput.value = '';
    };
    document.getElementById('results').appendChild(btn);
}