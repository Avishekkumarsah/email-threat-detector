/* =====================================================
   Email Threat Detector — main.js
   Handles: upload UX, drag-and-drop, scan loading,
            gauge chart, score breakdown, map
   ===================================================== */

/* ── Upload / Drop Zone ────────────────────────────── */
(function initUpload() {
  const dropZone   = document.getElementById('drop-zone');
  if (!dropZone) return;

  const fileInput       = document.getElementById('email_file');
  const scanForm        = document.getElementById('scan-form');
  const submitBtn       = document.getElementById('submit-btn');
  const scanLoader      = document.getElementById('scan-loader');
  const defaultState    = document.getElementById('upload-default-state');
  const selectedState   = document.getElementById('file-selected-state');
  const selectedName    = document.getElementById('selected-file-name');
  const selectedMeta    = document.getElementById('selected-file-meta');
  const removeBtn       = document.getElementById('file-remove-btn');

  // Click anywhere on drop zone → open picker
  dropZone.addEventListener('click', (e) => {
    if (e.target === removeBtn || removeBtn?.contains(e.target)) return;
    fileInput.click();
  });

  // Keyboard activation
  dropZone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
  });

  // Drag events
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', (e) => {
    if (!dropZone.contains(e.relatedTarget)) {
      dropZone.classList.remove('dragover');
    }
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
      setFile(e.dataTransfer.files[0]);
      fileInput.files = e.dataTransfer.files;
    }
  });

  // File picker change
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) setFile(fileInput.files[0]);
  });

  // Remove file
  if (removeBtn) {
    removeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      clearFile();
    });
  }

  function setFile(file) {
    if (!defaultState || !selectedState) return;
    selectedName.textContent = file.name;
    selectedMeta.textContent = `${file.type || 'Email file'} · ${formatBytes(file.size)}`;
    defaultState.style.display = 'none';
    selectedState.classList.add('visible');
  }

  function clearFile() {
    fileInput.value = '';
    if (defaultState) defaultState.style.display = '';
    if (selectedState) selectedState.classList.remove('visible');
  }

  function formatBytes(bytes) {
    if (!bytes) return '';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  // Form submit → show loader
  if (scanForm) {
    scanForm.addEventListener('submit', () => {
      if (!fileInput.files.length) return;
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span>⏳</span> Analyzing…';
      if (scanLoader) scanLoader.classList.add('visible');
    });
  }
})();


/* ── Result Page: Gauge chart ──────────────────────── */
(function initGauge() {
  if (typeof finalScore === 'undefined') return;
  const canvas = document.getElementById('gauge');
  if (!canvas || typeof Chart === 'undefined') return;

  const color = finalScore <= 30 ? '#16a34a' : finalScore <= 65 ? '#d97706' : '#dc2626';
  const bg    = finalScore <= 30 ? '#dcfce7'  : finalScore <= 65 ? '#fef9c3'  : '#fee2e2';

  new Chart(canvas, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [finalScore, 100 - finalScore],
        backgroundColor: [color, '#e2e8f0'],
        borderWidth: 0,
      }],
    },
    options: {
      circumference: 270,
      rotation: 225,
      cutout: '72%',
      animation: { animateRotate: true, duration: 900, easing: 'easeOutQuart' },
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false },
      },
    },
  });

  // Animate the score number
  const scoreEl = canvas.parentElement.querySelector('.score-number');
  if (scoreEl) {
    let current = 0;
    const step = Math.ceil(finalScore / 40);
    const timer = setInterval(() => {
      current = Math.min(current + step, finalScore);
      scoreEl.textContent = current;
      if (current >= finalScore) clearInterval(timer);
    }, 22);
  }
})();


/* ── Result Page: Map ──────────────────────────────── */
(function initMap() {
  if (typeof hops === 'undefined' || !hops.length) return;
  const mapEl = document.getElementById('map');
  if (!mapEl || typeof L === 'undefined') return;

  const validHops = hops.filter(h => h.lat != null && h.lon != null);
  if (!validHops.length) return;

  const map = L.map('map').setView([validHops[0].lat, validHops[0].lon], 3);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
  }).addTo(map);

  const latlngs = [];
  validHops.forEach((h) => {
    const marker = L.marker([h.lat, h.lon]).addTo(map);
    marker.bindPopup(`
      <div style="font-family:'Inter',sans-serif; min-width:160px;">
        <strong>Hop ${h.hop_number} — ${h.label || ''}</strong><br>
        <code style="font-size:11px;">${h.ip}</code><br>
        ${[h.city, h.country].filter(Boolean).join(', ')}<br>
        <span style="color:#64748b; font-size:11px;">${h.isp || ''}</span>
      </div>
    `);
    latlngs.push([h.lat, h.lon]);
  });

  if (latlngs.length > 1) {
    L.polyline(latlngs, { color: '#dc2626', weight: 2.5, dashArray: '7 6', opacity: 0.8 }).addTo(map);
    map.fitBounds(latlngs, { padding: [32, 32] });
  }
})();


/* ── History Page: Client-side search ─────────────── */
(function initSearch() {
  const searchBox = document.getElementById('search-box');
  if (!searchBox) return;

  searchBox.addEventListener('input', () => {
    const term = searchBox.value.toLowerCase().trim();
    const rows = document.querySelectorAll('#history-table tbody tr');
    let visible = 0;
    rows.forEach(row => {
      const match = !term || row.textContent.toLowerCase().includes(term);
      row.style.display = match ? '' : 'none';
      if (match) visible++;
    });
  });
})();
