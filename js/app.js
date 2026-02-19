/* ===========================================
   D-Drive — App Logic (Security Hardened)
   Uses DDriveSecurity module for all auth,
   sanitization, and data integrity.
   =========================================== */

(() => {
  'use strict';

  // ---- State ----
  let photos = [];
  let albums = [];
  let isAdmin = false;
  let currentFilter = 'all';
  let currentSearch = '';
  let largeGrid = false;
  let lightboxIndex = -1;
  let pendingFiles = [];

  // ---- Data Source Mode ----
  // Set to true to define images directly in code (no UI uploads).
  const CODE_LIBRARY_MODE = true;

  // Add your image files here (typically under /img) instead of uploading in UI.
  // Example:
  // { src: 'img/my-photo.jpg', album: 'Case A', tags: ['witness'], description: '...', createdAt: '2026-01-15' }
  const CODE_IMAGE_LIBRARY = [
    {
      src: 'img/backdrop.jpg',
      fileName: 'backdrop.jpg',
      album: 'Main Archive',
      tags: ['overview', 'scene'],
      description: 'Seed image loaded from code.',
      createdAt: '2026-01-10'
    },
    {
      src: 'img/avatar.png',
      fileName: 'avatar.png',
      album: 'Profiles',
      tags: ['profile'],
      description: 'Seed image loaded from code.',
      createdAt: '2026-01-12'
    }
  ];

  // ---- DOM ----
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const photoGrid = $('#photoGrid');
  const emptyState = $('#emptyState');
  const sectionTitle = $('#sectionTitle');
  const photoCount = $('#photoCount');
  const storageText = $('#storageText');
  const searchInput = $('#searchInput');
  const clearSearch = $('#clearSearch');
  const uploadBtn = $('#uploadBtn');
  const fileInput = $('#fileInput');
  const uploadZone = $('#uploadZone');
  const sidebar = $('#sidebar');
  const mainContent = $('#mainContent');
  const lightbox = $('#lightbox');
  const lightboxImg = $('#lightboxImg');
  const lightboxInfo = $('#lightboxInfo');
  const tagModal = $('#tagModal');
  const tagInput = $('#tagInput');
  const descInput = $('#descInput');
  const albumSelect = $('#albumSelect');
  const albumBar = $('#albumBar');
  const albumNameInput = $('#albumNameInput');
  const adminModal = $('#adminModal');
  const adminPasswordInput = $('#adminPasswordInput');
  const adminError = $('#adminError');
  const adminIcon = $('#adminIcon');
  const totalPhotosEl = $('#totalPhotos');
  const totalAlbumsEl = $('#totalAlbums');

  // ---- Secure Save/Load ----
  async function save() {
    if (CODE_LIBRARY_MODE) return;
    await DDriveSecurity.saveWithIntegrity('ddrive_photos', photos);
    await DDriveSecurity.saveWithIntegrity('ddrive_albums', albums);
  }

  function stableCodeId(seed, index) {
    let hash = 0;
    const text = `${seed}|${index}`;
    for (let i = 0; i < text.length; i++) {
      hash = ((hash << 5) - hash + text.charCodeAt(i)) | 0;
    }
    return `code_${index}_${Math.abs(hash)}`;
  }

  function parseCreatedAt(value, index) {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string' && value.trim()) {
      const parsed = Date.parse(value);
      if (Number.isFinite(parsed)) return parsed;
    }
    const fallbackBase = Date.now() - (CODE_IMAGE_LIBRARY.length * 24 * 60 * 60 * 1000);
    return fallbackBase + (index * 24 * 60 * 60 * 1000);
  }

  function normalizeCodeImageEntry(entry, index) {
    if (!entry || typeof entry !== 'object') return null;
    const src = typeof entry.src === 'string' ? entry.src.trim() : '';
    if (!src) return null;

    const fileName =
      (typeof entry.fileName === 'string' && entry.fileName.trim()) ||
      src.split('/').pop() ||
      `photo-${index + 1}.jpg`;

    const tags = Array.isArray(entry.tags)
      ? entry.tags.map(t => String(t).trim()).filter(Boolean)
      : [];

    const album = typeof entry.album === 'string' ? entry.album.trim() : '';
    const description = typeof entry.description === 'string' ? entry.description : '';

    return {
      id: (typeof entry.id === 'string' && entry.id.trim()) || stableCodeId(src, index),
      fileName,
      dataURL: src,
      tags: DDriveSecurity.sanitizeTags(tags),
      description: DDriveSecurity.sanitizeText(description).slice(0, 500),
      album: DDriveSecurity.sanitizeText(album),
      starred: Boolean(entry.starred),
      trashed: Boolean(entry.trashed),
      createdAt: parseCreatedAt(entry.createdAt, index)
    };
  }

  function loadCodeLibraryData() {
    const seededPhotos = CODE_IMAGE_LIBRARY
      .map(normalizeCodeImageEntry)
      .filter(Boolean);

    photos = seededPhotos;
    albums = Array.from(new Set(
      seededPhotos
        .map(p => p.album)
        .filter(Boolean)
    ));
  }

  async function loadData() {
    if (CODE_LIBRARY_MODE) {
      loadCodeLibraryData();
      return;
    }

    const photosResult = await DDriveSecurity.loadWithIntegrity('ddrive_photos');
    const albumsResult = await DDriveSecurity.loadWithIntegrity('ddrive_albums');

    if (!photosResult.valid) {
      console.warn('⚠️ Photo data integrity check failed! Data may have been tampered with.');
      if (!confirm('⚠️ Warning: Photo data may have been tampered with. Continue loading?')) {
        localStorage.removeItem('ddrive_photos');
        localStorage.removeItem('ddrive_photos_checksum');
        photos = [];
        albums = [];
        return;
      }
    }

    if (!albumsResult.valid) {
      console.warn('⚠️ Album data integrity check failed!');
    }

    photos = photosResult.data || [];
    albums = albumsResult.data || [];
  }

  // ---- Helpers ----
  function generateId() {
    const arr = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function formatDate(ts) {
    return new Date(ts).toLocaleDateString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric'
    });
  }

  function fileToDataURL(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  // ---- Admin UI Toggle ----
  function updateAdminUI() {
    $$('.admin-only').forEach(el => {
      el.style.display = isAdmin ? '' : 'none';
    });

    if (CODE_LIBRARY_MODE) {
      if (uploadBtn) uploadBtn.style.display = 'none';
      uploadZone.style.display = 'none';
      albumBar.style.display = 'none';
    }

    adminIcon.textContent = isAdmin ? 'lock_open' : 'lock';
    adminIcon.style.color = isAdmin ? '#4caf50' : '';

    const existing = $('#adminBanner');
    if (isAdmin && !existing) {
      const banner = document.createElement('div');
      banner.className = 'admin-banner';
      banner.id = 'adminBanner';
      banner.innerHTML = `
        <div style="display:flex;align-items:center;">
          <span class="material-icons">admin_panel_settings</span>
          <span>Admin mode — session expires after 30 min of inactivity</span>
        </div>
        <button id="adminLogoutBanner">Logout</button>
      `;
      const sectionHeader = $('#sectionHeader');
      if (sectionHeader) {
        sectionHeader.parentNode.insertBefore(banner, sectionHeader);
      }
      $('#adminLogoutBanner').addEventListener('click', adminLogout);
    } else if (!isAdmin && existing) {
      existing.remove();
    }

    if (!CODE_LIBRARY_MODE) {
      if (isAdmin && (currentFilter === 'all' || currentFilter === 'recent')) {
        uploadZone.style.display = '';
      } else {
        uploadZone.style.display = 'none';
      }
    }

    const emptyText = emptyState.querySelector('p');
    if (emptyText) {
      if (CODE_LIBRARY_MODE) {
        emptyText.textContent = 'Edit CODE_IMAGE_LIBRARY in js/app.js to add evidence images.';
      } else {
        emptyText.textContent = isAdmin
          ? 'Upload evidence to get started. Drag & drop or use the upload button.'
          : 'Check back later for updates.';
      }
    }
  }

  // ---- Auth (Secure) ----
  async function adminLogin() {
    const password = adminPasswordInput.value;
    adminPasswordInput.value = ''; // Clear immediately

    // Check rate limit
    const rateInfo = DDriveSecurity.getRateLimitInfo();
    if (rateInfo.locked) {
      adminError.textContent = `Locked out. Try again in ${rateInfo.remainingSeconds} seconds.`;
      adminError.style.display = 'block';
      return;
    }

    const result = await DDriveSecurity.verifyPassword(password);

    if (result.success) {
      isAdmin = true;
      adminModal.classList.remove('active');
      adminError.style.display = 'none';
      updateAdminUI();
      render();
    } else {
      adminError.textContent = result.error;
      adminError.style.display = 'block';
      adminPasswordInput.focus();
    }
  }

  function adminLogout() {
    isAdmin = false;
    DDriveSecurity.destroySession();
    updateAdminUI();
    if (currentFilter === 'trash') {
      currentFilter = 'all';
      $$('.sidebar-link').forEach(l => {
        l.classList.toggle('active', l.dataset.filter === 'all');
      });
    }
    render();
  }

  // Register logout callback for session timeout
  window._ddrive_logout = () => {
    if (isAdmin) {
      isAdmin = false;
      updateAdminUI();
      render();
      alert('Session expired due to inactivity. Please log in again.');
    }
  };

  // ---- Filtering ----
  function getFilteredPhotos() {
    let list = photos.filter(p => !p.trashed);

    if (currentFilter === 'starred') {
      list = list.filter(p => p.starred);
    } else if (currentFilter === 'recent') {
      list = [...list].sort((a, b) => b.createdAt - a.createdAt).slice(0, 50);
    } else if (currentFilter === 'trash') {
      list = photos.filter(p => p.trashed);
    } else if (currentFilter.startsWith('album:')) {
      const albumName = currentFilter.replace('album:', '');
      list = list.filter(p => p.album === albumName);
    }

    if (currentSearch) {
      const q = DDriveSecurity.sanitizeText(currentSearch.toLowerCase());
      list = list.filter(p =>
        (p.tags || []).some(t => t.toLowerCase().includes(q)) ||
        (p.description || '').toLowerCase().includes(q) ||
        (p.fileName || '').toLowerCase().includes(q)
      );
    }

    return list;
  }

  // ---- Render Helpers ----
  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function getFolderBuckets(list) {
    const map = new Map();
    list.forEach(photo => {
      const albumName = (photo.album || '').trim();
      const key = albumName || '__unfiled__';
      if (!map.has(key)) {
        map.set(key, {
          key,
          album: albumName,
          label: albumName || 'Unfiled',
          photos: []
        });
      }
      map.get(key).photos.push(photo);
    });

    return Array.from(map.values())
      .sort((a, b) => b.photos.length - a.photos.length || a.label.localeCompare(b.label));
  }

  function attachNetworkEvents() {
    photoGrid.querySelectorAll('.photo-node').forEach(node => {
      node.addEventListener('click', (e) => {
        if (e.target.closest('[data-action]')) return;
        openLightbox(node.dataset.id);
      });

      node.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          openLightbox(node.dataset.id);
        }
      });
    });

    photoGrid.querySelectorAll('.folder-node[data-folder-action]').forEach(node => {
      const action = node.dataset.folderAction;
      if (!action) return;

      node.addEventListener('click', () => {
        if (action === 'album') {
          const albumName = decodeURIComponent(node.dataset.album || '');
          if (!albumName) return;
          currentFilter = 'album:' + albumName;
          $$('.sidebar-link').forEach(l => {
            l.classList.toggle('active', l.dataset.filter === 'albums');
          });
        } else if (action === 'unfiled') {
          currentFilter = 'all';
          $$('.sidebar-link').forEach(l => {
            l.classList.toggle('active', l.dataset.filter === 'all');
          });
        }
        updateAdminUI();
        render();
      });
    });

    if (isAdmin) {
      photoGrid.querySelectorAll('[data-action="star"]').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          toggleStar(btn.dataset.id);
        });
      });
    }
  }

  function renderNetworkView(list, folderOnly = false) {
    const width = Math.max(photoGrid.clientWidth || 900, 360);
    const height = Math.max(folderOnly ? 520 : 620, Math.round(width * (folderOnly ? 0.58 : 0.66)));
    const centerX = width / 2;
    const centerY = height / 2;

    const activePhotos = photos.filter(p => !p.trashed);
    let buckets = [];

    if (folderOnly) {
      const counts = new Map();
      activePhotos.forEach(p => {
        const key = (p.album || '').trim() || '__unfiled__';
        counts.set(key, (counts.get(key) || 0) + 1);
      });

      buckets = albums.map(name => ({
        album: name,
        label: name,
        count: counts.get(name) || 0,
        photos: []
      }));

      const unfiledCount = counts.get('__unfiled__') || 0;
      if (unfiledCount > 0) {
        buckets.push({
          album: '',
          label: 'Unfiled',
          count: unfiledCount,
          photos: []
        });
      }
    } else {
      buckets = getFolderBuckets(list).map(bucket => ({
        ...bucket,
        count: bucket.photos.length
      }));
    }

    photoGrid.classList.add('network-map');
    photoGrid.classList.toggle('large', largeGrid);
    photoGrid.classList.toggle('folders-only', folderOnly);
    photoGrid.style.height = `${height}px`;

    if (buckets.length === 0) {
      photoGrid.innerHTML = `<div class="network-empty-note">${
        folderOnly
          ? (isAdmin ? 'No case files yet. Create one above.' : 'No case files yet.')
          : 'No evidence in this view.'
      }</div>`;
      return;
    }

    const lines = [];
    const nodes = [];
    const folderPositions = [];
    const folderCount = buckets.length;
    const orbit = Math.min(width, height) * (
      folderCount <= 1
        ? 0.20
        : folderOnly
          ? 0.34
          : (folderCount < 4 ? 0.25 : 0.30)
    );

    nodes.push(`
      <div class="network-node hub-node" style="left:${centerX}px;top:${centerY}px;">
        <span class="material-icons">${folderOnly ? 'folder_special' : 'hub'}</span>
        <span class="hub-title">${folderOnly ? 'Folder Hub' : 'Archive Hub'}</span>
      </div>
    `);

    buckets.forEach((bucket, index) => {
      let angle = -Math.PI / 2 + ((Math.PI * 2) * index / Math.max(folderCount, 1));
      if (folderCount === 1) angle = -Math.PI / 2;
      const x = clamp(centerX + Math.cos(angle) * orbit, 88, width - 88);
      const y = clamp(centerY + Math.sin(angle) * orbit, 84, height - 84);

      folderPositions.push({ x, y });
      lines.push(`<line class="web-link hub-link" x1="${centerX}" y1="${centerY}" x2="${x}" y2="${y}"></line>`);

      const safeLabel = DDriveSecurity.sanitizeText(bucket.label);
      const action = bucket.album
        ? 'album'
        : (folderOnly ? 'unfiled' : '');
      const buttonClass = action ? 'folder-node folder-node-clickable' : 'folder-node';

      nodes.push(`
        <button type="button" class="network-node ${buttonClass}" data-folder-action="${action}" data-album="${encodeURIComponent(bucket.album || '')}" style="left:${x}px;top:${y}px;" ${action ? '' : 'disabled'}>
          <span class="material-icons">${bucket.album ? 'folder' : 'folder_open'}</span>
          <span class="folder-label">${safeLabel}</span>
          <span class="folder-count">${bucket.count}</span>
        </button>
      `);

      if (folderOnly) return;

      const maxPerFolder = 16;
      const photosToShow = bucket.photos.slice(0, maxPerFolder);
      const hiddenCount = bucket.photos.length - photosToShow.length;
      const spread = photosToShow.length <= 1
        ? 0
        : Math.min(Math.PI * 1.45, 0.92 + photosToShow.length * 0.2);

      photosToShow.forEach((photo, photoIndex) => {
        const t = photosToShow.length <= 1 ? 0 : (photoIndex / (photosToShow.length - 1) - 0.5);
        const theta = angle + (t * spread) + ((photoIndex % 2 === 0) ? 0.05 : -0.05);
        const ring = Math.floor(photoIndex / 8);
        const distance = 96 + (ring * 52) + ((photoIndex % 3) * 3);
        const px = clamp(x + Math.cos(theta) * distance, 44, width - 44);
        const py = clamp(y + Math.sin(theta) * distance, 44, height - 44);
        const safeName = DDriveSecurity.sanitizeText(photo.fileName);
        const safeId = DDriveSecurity.sanitizeText(photo.id);
        const safeDate = DDriveSecurity.sanitizeText(formatDate(photo.createdAt));

        lines.push(`<line class="web-link photo-link" x1="${x}" y1="${y}" x2="${px}" y2="${py}"></line>`);

        nodes.push(`
          <div class="network-node photo-node" role="button" tabindex="0" data-id="${safeId}" style="left:${px}px;top:${py}px;" aria-label="Open ${safeName}">
            <img src="${photo.dataURL}" alt="${safeName}" loading="lazy" />
            ${photo.starred ? '<span class="photo-badge material-icons">star</span>' : ''}
            ${isAdmin ? `
              <button class="node-star-btn ${photo.starred ? 'starred' : ''}" data-action="star" data-id="${safeId}" title="Toggle key evidence">
                <span class="material-icons">${photo.starred ? 'star' : 'star_border'}</span>
              </button>
            ` : ''}
            <span class="photo-label">${safeName}</span>
            <span class="photo-date">${safeDate}</span>
          </div>
        `);
      });

      if (hiddenCount > 0) {
        nodes.push(`
          <div class="network-node folder-overflow" style="left:${x}px;top:${y + 52}px;">
            +${hiddenCount} more
          </div>
        `);
      }
    });

    if (folderPositions.length > 2) {
      for (let i = 0; i < folderPositions.length; i++) {
        const current = folderPositions[i];
        const next = folderPositions[(i + 1) % folderPositions.length];
        lines.push(`<line class="web-link ring-link" x1="${current.x}" y1="${current.y}" x2="${next.x}" y2="${next.y}"></line>`);
      }
    }

    const rings = [0.20, 0.32, 0.44]
      .map(factor => `<circle class="web-ring" cx="${centerX}" cy="${centerY}" r="${Math.round(Math.min(width, height) * factor)}"></circle>`)
      .join('');

    photoGrid.innerHTML = `
      <svg class="network-web" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-hidden="true">
        ${rings}
        ${lines.join('')}
      </svg>
      <div class="network-layer">
        ${nodes.join('')}
      </div>
      <div class="network-legend">
        <span><i class="material-icons">hub</i> Hub</span>
        <span><i class="material-icons">folder</i> Folder</span>
        ${folderOnly ? '' : '<span><i class="material-icons">photo</i> Photo</span>'}
      </div>
    `;

    attachNetworkEvents();
  }

  // ---- Render (with sanitized output) ----
  function render() {
    const filtered = getFilteredPhotos();
    const total = photos.filter(p => !p.trashed).length;

    storageText.textContent = `${total} photo${total !== 1 ? 's' : ''}`;
    totalPhotosEl.textContent = total;
    totalAlbumsEl.textContent = albums.length;
    photoCount.textContent = `${filtered.length} photo${filtered.length !== 1 ? 's' : ''}`;

    const titles = {
      all: 'All Evidence Network',
      starred: 'Key Evidence Network',
      recent: 'Recent Upload Network',
      trash: 'Trash Network',
      albums: 'Case File Network'
    };
    if (currentFilter.startsWith('album:')) {
      sectionTitle.textContent = 'Case File: ' + DDriveSecurity.sanitizeText(currentFilter.replace('album:', ''));
    } else {
      sectionTitle.textContent = titles[currentFilter] || 'All Evidence Network';
    }

    if (currentFilter === 'albums') { renderAlbumsView(); return; }

    if (CODE_LIBRARY_MODE || !isAdmin || currentFilter !== 'albums') {
      albumBar.style.display = 'none';
    }

    if (filtered.length === 0) {
      photoGrid.innerHTML = '';
      photoGrid.style.height = '';
      photoGrid.classList.remove('network-map', 'folders-only');
      emptyState.style.display = 'block';
      return;
    }

    emptyState.style.display = 'none';
    renderNetworkView(filtered, false);
  }

  function renderAlbumsView() {
    const activePhotos = photos.filter(p => !p.trashed);
    const unfiledCount = activePhotos.filter(p => !(p.album || '').trim()).length;
    const folderCount = albums.length + (unfiledCount > 0 ? 1 : 0);

    emptyState.style.display = 'none';
    albumBar.style.display = (!CODE_LIBRARY_MODE && isAdmin) ? 'flex' : 'none';
    photoCount.textContent = `${folderCount} folder${folderCount !== 1 ? 's' : ''}`;

    renderNetworkView(activePhotos, true);
  }

  // ---- Actions ----
  function toggleStar(id) {
    if (!isAdmin) return;
    const photo = photos.find(p => p.id === id);
    if (photo) { photo.starred = !photo.starred; save(); render(); }
  }

  function deletePhoto(id) {
    if (!isAdmin) return;
    const photo = photos.find(p => p.id === id);
    if (photo) {
      if (currentFilter === 'trash') {
        photos = photos.filter(p => p.id !== id);
      } else {
        photo.trashed = true;
      }
      save(); render();
    }
  }

  // ---- Lightbox ----
  function openLightbox(id) {
    const filtered = getFilteredPhotos();
    lightboxIndex = filtered.findIndex(p => p.id === id);
    if (lightboxIndex < 0) return;
    showLightboxPhoto(filtered[lightboxIndex]);
    lightbox.classList.add('active');
    document.body.style.overflow = 'hidden';
  }

  function showLightboxPhoto(photo) {
    lightboxImg.src = photo.dataURL;
    lightboxImg.alt = DDriveSecurity.sanitizeText(photo.fileName);
    const safeName = DDriveSecurity.sanitizeText(photo.fileName);
    const safeDesc = DDriveSecurity.sanitizeText(photo.description || '');
    const safeTags = (photo.tags || []).map(t => DDriveSecurity.sanitizeText(t));
    let info = `<strong>${safeName}</strong> &nbsp;·&nbsp; ${formatDate(photo.createdAt)}`;
    if (safeDesc) info += ` &nbsp;·&nbsp; ${safeDesc}`;
    if (safeTags.length) info += ` &nbsp;·&nbsp; <em>${safeTags.join(', ')}</em>`;
    lightboxInfo.innerHTML = info;

    const starBtn = $('#lbStar');
    if (isAdmin) {
      starBtn.innerHTML = `<span class="material-icons">${photo.starred ? 'star' : 'star_border'}</span>`;
      starBtn.style.color = photo.starred ? 'var(--star-color)' : '#fff';
    }
  }

  function closeLightbox() {
    lightbox.classList.remove('active');
    document.body.style.overflow = '';
    lightboxIndex = -1;
  }

  function navigateLightbox(dir) {
    const filtered = getFilteredPhotos();
    lightboxIndex += dir;
    if (lightboxIndex < 0) lightboxIndex = filtered.length - 1;
    if (lightboxIndex >= filtered.length) lightboxIndex = 0;
    showLightboxPhoto(filtered[lightboxIndex]);
  }

  // ---- Upload (Validated & Sanitized) ----
  async function handleFiles(files) {
    if (CODE_LIBRARY_MODE) {
      alert('UI upload is disabled. Add images in js/app.js -> CODE_IMAGE_LIBRARY.');
      return;
    }
    if (!isAdmin) return;
    if (files.length === 0) return;

    // Validate all files
    const validFiles = [];
    const errors = [];

    Array.from(files).forEach(file => {
      const validation = DDriveSecurity.validateImageFile(file);
      if (validation.valid) {
        validFiles.push(file);
      } else {
        errors.push(`${file.name}: ${validation.errors.join(', ')}`);
      }
    });

    if (errors.length > 0) {
      alert('⚠️ Some files were rejected:\n\n' + errors.join('\n'));
    }

    if (validFiles.length === 0) return;

    pendingFiles = validFiles;
    $('#modalFileCount').textContent = `${pendingFiles.length} file${pendingFiles.length !== 1 ? 's' : ''} selected`;
    updateAlbumSelect();
    tagInput.value = '';
    descInput.value = '';
    tagModal.classList.add('active');
  }

  async function processUpload(tags, description, album) {
    if (CODE_LIBRARY_MODE) return;
    if (!isAdmin) return;
    for (const file of pendingFiles) {
      try {
        const dataURL = await fileToDataURL(file);
        photos.push({
          id: generateId(),
          fileName: DDriveSecurity.sanitizeFileName(file.name),
          dataURL,
          tags: DDriveSecurity.sanitizeTags(tags),
          description: DDriveSecurity.sanitizeText(description).slice(0, 500),
          album: DDriveSecurity.sanitizeText(album || ''),
          starred: false,
          trashed: false,
          createdAt: Date.now()
        });
      } catch (err) {
        console.error('Failed to process file:', file.name, err);
      }
    }
    pendingFiles = [];
    await save();
    render();
  }

  function updateAlbumSelect() {
    albumSelect.innerHTML = '<option value="">No case file</option>';
    albums.forEach(a => {
      const safe = DDriveSecurity.sanitizeText(a);
      albumSelect.innerHTML += `<option value="${safe}">${safe}</option>`;
    });
  }

  // ---- Event Listeners ----

  $$('.sidebar-link').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      if (link.dataset.filter === 'trash' && !isAdmin) return;
      $$('.sidebar-link').forEach(l => l.classList.remove('active'));
      link.classList.add('active');
      currentFilter = link.dataset.filter;
      updateAdminUI();
      render();
    });
  });

  $('#menuToggle').addEventListener('click', () => {
    sidebar.classList.toggle('collapsed');
    sidebar.classList.toggle('open');
    mainContent.classList.toggle('expanded');
    if (photoGrid.classList.contains('network-map')) {
      setTimeout(render, 220);
    }
  });

  searchInput.addEventListener('input', () => {
    currentSearch = searchInput.value.trim();
    clearSearch.style.display = currentSearch ? 'flex' : 'none';
    render();
  });
  clearSearch.addEventListener('click', () => {
    searchInput.value = '';
    currentSearch = '';
    clearSearch.style.display = 'none';
    render();
  });

  $('#gridToggle').addEventListener('click', () => {
    largeGrid = !largeGrid;
    render();
  });

  let resizeTimer = null;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (photoGrid.classList.contains('network-map')) {
        render();
      }
    }, 120);
  });

  if (!CODE_LIBRARY_MODE) {
    if (uploadBtn) {
      uploadBtn.addEventListener('click', () => { if (isAdmin) fileInput.click(); });
    }
    fileInput.addEventListener('change', () => { if (isAdmin) handleFiles(fileInput.files); });
    uploadZone.addEventListener('click', () => { if (isAdmin) fileInput.click(); });

    uploadZone.addEventListener('dragover', (e) => { if (!isAdmin) return; e.preventDefault(); uploadZone.classList.add('dragover'); });
    uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragover'));
    uploadZone.addEventListener('drop', (e) => { e.preventDefault(); uploadZone.classList.remove('dragover'); if (isAdmin) handleFiles(e.dataTransfer.files); });

    document.body.addEventListener('dragover', (e) => e.preventDefault());
    document.body.addEventListener('drop', (e) => { e.preventDefault(); if (isAdmin && e.dataTransfer.files.length) handleFiles(e.dataTransfer.files); });
  }

  $('#saveTagBtn').addEventListener('click', () => {
    const tags = tagInput.value.split(',').map(t => t.trim()).filter(Boolean);
    const desc = descInput.value.trim();
    const album = albumSelect.value;
    tagModal.classList.remove('active');
    processUpload(tags, desc, album);
  });
  $('#skipTagBtn').addEventListener('click', () => { tagModal.classList.remove('active'); processUpload([], '', ''); });

  $('#createAlbumBtn').addEventListener('click', async () => {
    if (CODE_LIBRARY_MODE) return;
    if (!isAdmin) return;
    const name = DDriveSecurity.sanitizeText(albumNameInput.value.trim());
    if (name && name.length <= 100 && !albums.includes(name)) {
      albums.push(name);
      await save();
      albumNameInput.value = '';
      render();
    }
  });

  // Admin
  $('#adminToggle').addEventListener('click', () => {
    if (isAdmin) { adminLogout(); }
    else {
      adminPasswordInput.value = '';
      adminError.style.display = 'none';
      adminModal.classList.add('active');
      setTimeout(() => adminPasswordInput.focus(), 100);
    }
  });

  $('#adminLoginBtn').addEventListener('click', adminLogin);
  $('#adminCancelBtn').addEventListener('click', () => { adminModal.classList.remove('active'); });
  adminPasswordInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') adminLogin(); });

  // Lightbox
  $('#lbClose').addEventListener('click', closeLightbox);
  $('#lbPrev').addEventListener('click', () => navigateLightbox(-1));
  $('#lbNext').addEventListener('click', () => navigateLightbox(1));

  $('#lbStar').addEventListener('click', () => {
    if (!isAdmin) return;
    const filtered = getFilteredPhotos();
    if (lightboxIndex >= 0) { toggleStar(filtered[lightboxIndex].id); showLightboxPhoto(photos.find(p => p.id === filtered[lightboxIndex].id)); }
  });

  $('#lbDownload').addEventListener('click', () => {
    const filtered = getFilteredPhotos();
    if (lightboxIndex >= 0) {
      const photo = filtered[lightboxIndex];
      const a = document.createElement('a');
      a.href = photo.dataURL;
      a.download = photo.fileName;
      a.click();
    }
  });

  $('#lbDelete').addEventListener('click', () => {
    if (!isAdmin) return;
    const filtered = getFilteredPhotos();
    if (lightboxIndex >= 0) { deletePhoto(filtered[lightboxIndex].id); closeLightbox(); }
  });

  document.addEventListener('keydown', (e) => {
    if (adminModal.classList.contains('active')) return;
    if (!lightbox.classList.contains('active')) return;
    if (e.key === 'Escape') closeLightbox();
    if (e.key === 'ArrowLeft') navigateLightbox(-1);
    if (e.key === 'ArrowRight') navigateLightbox(1);
  });

  // ---- Init ----
  async function init() {
    // Enforce security
    DDriveSecurity.enforceCSP();

    // Load data with integrity check
    await loadData();

    // Restore session
    if (DDriveSecurity.isSessionValid()) {
      isAdmin = true;
    }

    updateAdminUI();
    render();
  }

  init();

})();
