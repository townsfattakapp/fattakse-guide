// FattakSe Guide viewer: unlocks the encrypted guide in the browser and shows it.
// Files written by build_site.py: data/k.json = PBKDF2 salt and iterations; data/m.bin = menu and search
// text; data/<id>.bin = one page; data/i/<id>.bin = one picture. Every .bin is IV (12 bytes) + AES-256-GCM.
'use strict';

(() => {
  const section = document.body.dataset.section;
  const STORE = `ftk-guide:${section}:key`;
  const $ = (id) => document.getElementById(id);
  const utf8 = new TextDecoder();

  let aesKey = null;
  let manifest = null;
  let order = [];
  let searching = false;
  let searchTimer = null;
  let watcher = null;
  const pages = new Map();
  const pictures = new Map();

  const toB64 = (bytes) => btoa(String.fromCharCode(...bytes));
  const fromB64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
  const escapeHtml = (text) => String(text).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // The derived key (never the password) is kept for this tab, or on this device when "Remember" is ticked.
  function readKey() {
    try { return localStorage.getItem(STORE) || sessionStorage.getItem(STORE); } catch (e) { return null; }
  }
  function saveKey(raw, remember) {
    try { (remember ? localStorage : sessionStorage).setItem(STORE, toB64(raw)); } catch (e) { /* private mode: ask again next time */ }
  }
  function forgetKey() {
    try { localStorage.removeItem(STORE); sessionStorage.removeItem(STORE); } catch (e) { /* nothing was stored */ }
  }

  async function getBytes(path, fresh) {
    const res = await fetch(path, fresh ? { cache: 'no-cache' } : {});
    if (!res.ok) throw new Error(`could not download ${path} (HTTP ${res.status})`);
    return new Uint8Array(await res.arrayBuffer());
  }

  async function decrypt(bytes) {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12) }, aesKey, bytes.subarray(12));
    return new Uint8Array(plain);
  }

  async function keyFromPassword(password) {
    const res = await fetch('data/k.json', { cache: 'no-cache' });
    if (!res.ok) throw new Error(`could not download the guide (HTTP ${res.status})`);
    const params = await res.json();
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password.trim().toLowerCase()), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(params.salt), iterations: params.iter }, base, 256);
    return new Uint8Array(bits);
  }

  async function unlock(raw) {
    aesKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    manifest = JSON.parse(utf8.decode(await decrypt(await getBytes('data/m.bin', true))));
    order = manifest.groups.flatMap((group) => group.pages);
  }

  function showLock(message) {
    $('boot').hidden = true;
    $('app').hidden = true;
    $('lock').hidden = false;
    $('lock-msg').textContent = message || '';
    $('pw').focus();
  }

  function startApp() {
    $('boot').hidden = true;
    $('lock').hidden = true;
    $('app').hidden = false;
    document.querySelector('.top .tag').textContent = manifest.label;
    buildNav();
    $('foot').textContent = `Updated ${manifest.built}. For the FattakSe team only: do not share the password outside the team.`;
    route();
  }

  function buildNav() {
    const nav = $('nav');
    nav.textContent = '';
    for (const group of manifest.groups) {
      const head = document.createElement('div');
      head.className = 'nav-group';
      head.textContent = group.name;
      nav.append(head);
      for (const id of group.pages) {
        const link = document.createElement('a');
        link.href = `#/${id}`;
        link.dataset.id = id;
        link.textContent = manifest.pages[id].t;
        nav.append(link);
      }
    }
  }

  function current() {
    const [id, ...rest] = decodeURIComponent(location.hash.replace(/^#\/?/, '')).split('/');
    return { id: manifest.pages[id] ? id : manifest.home, anchor: rest.join('/') };
  }

  async function route() {
    if (!manifest) return;
    if (searching) {
      searching = false;
      $('search').value = '';
    }
    const { id, anchor } = current();
    await showPage(id, anchor);
  }

  async function showPage(id, anchor) {
    const meta = manifest.pages[id];
    document.title = `${meta.t} · FattakSe Guide`;
    for (const link of $('nav').querySelectorAll('a')) {
      if (link.dataset.id === id) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    }
    document.body.classList.remove('nav-open');
    const article = $('page');
    let html = pages.get(id);
    if (!html) {
      article.innerHTML = '<p class="muted">Loading…</p>';
      $('pager').textContent = '';
      try {
        html = utf8.decode(await decrypt(await getBytes(`data/${meta.f}.bin`)));
        pages.set(id, html);
      } catch (error) {
        article.innerHTML = `<p class="msg">This page could not be loaded: ${escapeHtml(error.message || error)}. Check the internet connection and try again.</p>`;
        return;
      }
      if (current().id !== id || searching) return;
    }
    article.innerHTML = html;
    watchPictures(article);
    showPager(id);
    const target = anchor && document.getElementById(anchor);
    if (target) target.scrollIntoView();
    else window.scrollTo(0, 0);
  }

  // Pictures are separate encrypted files, fetched when they come near the screen.
  function watchPictures(root) {
    if (!watcher) {
      watcher = new IntersectionObserver((entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          watcher.unobserve(entry.target);
          showPicture(entry.target);
        }
      }, { rootMargin: '800px 0px' });
    }
    for (const img of root.querySelectorAll('img[data-blob]')) watcher.observe(img);
  }

  async function showPicture(img) {
    const id = img.dataset.blob;
    try {
      if (!pictures.has(id)) {
        pictures.set(id, getBytes(`data/i/${id}.bin`).then(decrypt)
          .then((bytes) => URL.createObjectURL(new Blob([bytes], { type: 'image/webp' }))));
      }
      img.src = await pictures.get(id);
      img.classList.add('loaded');
    } catch (error) {
      pictures.delete(id);
      img.classList.add('failed');
      img.alt = 'This picture could not be loaded.';
    }
  }

  function openPicture(img) {
    const box = $('lightbox');
    box.textContent = '';
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'lb-close';
    close.textContent = 'Close ✕';
    const big = document.createElement('img');
    big.src = img.src;
    big.alt = img.alt;
    box.append(close, big);
    box.hidden = false;
    document.body.classList.add('no-scroll');
    close.focus();
  }

  function closePicture() {
    const box = $('lightbox');
    if (box.hidden) return;
    box.hidden = true;
    box.textContent = '';
    document.body.classList.remove('no-scroll');
  }

  function showPager(id) {
    const box = $('pager');
    box.textContent = '';
    const at = order.indexOf(id);
    const add = (target, label, cls) => {
      const link = document.createElement('a');
      link.href = `#/${target}`;
      link.className = cls;
      link.innerHTML = `<small>${label}</small>${escapeHtml(manifest.pages[target].t)}`;
      box.append(link);
    };
    if (at > 0) add(order[at - 1], 'Previous', 'prev');
    if (at >= 0 && at < order.length - 1) add(order[at + 1], 'Next', 'next');
  }

  function runSearch() {
    const query = $('search').value.trim().toLowerCase();
    if (query.length < 2) {
      if (searching) {
        searching = false;
        route();
      }
      return;
    }
    searching = true;
    const words = query.split(/\s+/);
    const hits = [];
    for (const id of order) {
      const text = manifest.text[id] || '';
      const lower = text.toLowerCase();
      const title = manifest.pages[id].t.toLowerCase();
      if (!words.every((w) => lower.includes(w) || title.includes(w))) continue;
      let score = title.includes(query) ? 50 : 0;
      for (const w of words) score += Math.min(lower.split(w).length - 1, 20) + (title.includes(w) ? 10 : 0);
      hits.push({ id, score, snippet: snippet(text, lower, words) });
    }
    hits.sort((a, b) => b.score - a.score);
    const list = hits.slice(0, 40).map((hit) => `<a href="#/${hit.id}"><span class="r-title">${escapeHtml(manifest.pages[hit.id].t)}</span>`
      + `<span class="r-group">${escapeHtml(manifest.pages[hit.id].g)}</span><span class="r-snip">${hit.snippet}</span></a>`).join('');
    $('page').innerHTML = `<h1>Search: ${escapeHtml(query)}</h1>`
      + (hits.length ? `<div class="results">${list}</div>` : '<p class="muted">Nothing found. Try another word.</p>');
    $('pager').textContent = '';
    for (const link of $('page').querySelectorAll('.results a')) {
      link.addEventListener('click', (event) => {
        event.preventDefault();
        searching = false;
        $('search').value = '';
        if (location.hash === link.getAttribute('href')) route();
        else location.hash = link.getAttribute('href');
      });
    }
  }

  function snippet(text, lower, words) {
    const at = Math.max(0, lower.indexOf(words.find((w) => lower.includes(w)) || ''));
    const start = Math.max(0, at - 60);
    const part = escapeHtml((start ? '…' : '') + text.slice(start, at + 140) + (at + 140 < text.length ? '…' : ''));
    const pattern = new RegExp(words.map((w) => escapeHtml(w).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'gi');
    return part.replace(pattern, (m) => `<mark>${m}</mark>`);
  }

  $('pw-show').addEventListener('click', () => {
    const input = $('pw');
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    $('pw-show').textContent = show ? 'Hide' : 'Show';
  });

  $('lock-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const password = $('pw').value;
    if (!password.trim()) return;
    const button = $('unlock');
    button.disabled = true;
    button.textContent = 'Opening…';
    $('lock-msg').textContent = '';
    try {
      const raw = await keyFromPassword(password);
      await unlock(raw);
      saveKey(raw, $('remember').checked);
      $('pw').value = '';
      startApp();
    } catch (error) {
      aesKey = null;
      manifest = null;
      $('lock-msg').textContent = error && error.name === 'OperationError'
        ? 'Wrong password. Please check it and try again.'
        : `The guide could not be opened: ${error.message || error}. Check the internet connection.`;
    } finally {
      button.disabled = false;
      button.textContent = 'Open the guide';
    }
  });

  $('search').addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(runSearch, 150);
  });
  $('search').addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    const first = $('page').querySelector('.results a');
    if (first) first.click();
  });
  $('page').addEventListener('click', (event) => {
    const img = event.target.closest('img.shot.loaded');
    if (img) openPicture(img);
  });
  $('lightbox').addEventListener('click', (event) => {
    if (event.target.tagName !== 'IMG') closePicture();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    closePicture();
    document.body.classList.remove('nav-open');
  });
  $('menu-btn').addEventListener('click', () => document.body.classList.toggle('nav-open'));
  $('scrim').addEventListener('click', () => document.body.classList.remove('nav-open'));
  $('lock-btn').addEventListener('click', () => {
    forgetKey();
    location.hash = '';
    location.reload();
  });
  window.addEventListener('hashchange', route);

  async function boot() {
    if (!window.crypto || !crypto.subtle) {
      showLock('This browser cannot open the guide. Please use an up-to-date Chrome, Safari or Edge.');
      $('unlock').disabled = true;
      return;
    }
    const stored = readKey();
    if (stored) {
      try {
        await unlock(fromB64(stored));
        startApp();
        return;
      } catch (error) {
        aesKey = null;
        manifest = null;
        if (!error || error.name !== 'OperationError') {
          showLock(`The guide could not be opened: ${error.message || error}. Check the internet connection.`);
          return;
        }
        forgetKey(); // the password was changed since the last visit
      }
    }
    showLock();
  }

  boot();
})();
