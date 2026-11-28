export function guestPage(owner: boolean) {
  const heading = 'Приглашение в Torsher'
  const instructions = owner
    ? 'Ссылка действует 24 часа. По ней можно подключить один браузер и один телевизор к выбранному профилю.'
    : 'Смотри в браузере на этом устройстве или подключи телевизор по QR-коду.'
  const fields = owner
    ? '<label>Профиль<select name="profile" required></select></label><label>Имя гостя<input name="name" maxlength="80" required placeholder="Например, Анна"></label><button type="submit" disabled>Создать ссылку</button>'
    : `<button type="button" id="scan" disabled>Сканировать QR с телевизора</button>
<div id="scanner" hidden><video playsinline muted aria-label="Камера для QR-кода"></video><button type="button" id="stop-camera">Закрыть камеру</button></div>
<details id="manual"><summary>Ввести код вручную</summary>
<label>Код с телевизора<input name="code" maxlength="12" autocapitalize="characters" autocomplete="off" required placeholder="ABC-234"></label>
<button type="submit" disabled>Подключить телевизор</button></details>`
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${heading} · Torsher</title><style nonce="GUEST_NONCE">
[hidden]{display:none!important}*{box-sizing:border-box}body{margin:0;background:#111214;color:#f5f5f5;font:17px/1.5 system-ui,sans-serif}main{width:min(100% - 2rem,32rem);margin:clamp(1.5rem,8vw,5rem) auto}h1{line-height:1.15;font-size:clamp(1.7rem,7vw,2.5rem)}p{color:#c8cbd0}label{display:block;margin-block:1rem}input,select,button{display:block;width:100%;margin-top:.4rem;padding:.75rem;border:1px solid #666;border-radius:8px;font:inherit}input,select{background:#222;color:#fff}button{background:#f1c053;color:#19150b;font-weight:700;cursor:pointer}form[data-owner="false"]{border-top:1px solid #404247;margin-top:1.5rem;padding-top:.5rem}form[data-owner="false"] button{background:#222;color:#fff}button:disabled{opacity:.6}output{display:block;margin-top:1rem;min-height:1.5em}
details{margin-top:1rem}summary{color:#c8cbd0;cursor:pointer}video{display:block;width:100%;max-height:44vh;margin-top:1rem;border-radius:8px;background:#222}
</style></head><body><main><h1>${heading}</h1><p>${instructions}</p>
${owner ? '' : '<button id="browser" type="button" disabled>Смотреть в браузере</button>'}
<form id="setup" data-owner="${owner}">${fields}</form>
<output id="status" aria-live="polite"></output>
<label id="link" hidden>Ссылка для гостя<input readonly autocomplete="off"></label>
</main><script src="${owner ? '/guest-invites.js' : '/activate.js'}" defer></script></body></html>`
}

export const guestPageScript = `
const form = document.querySelector('#setup');
const status = document.querySelector('#status');
const link = document.querySelector('#link');
const button = form.querySelector('button[type="submit"]');
const browserButton = document.querySelector('#browser');
const scanButton = document.querySelector('#scan');
const scanner = document.querySelector('#scanner');
const video = scanner?.querySelector('video');
const manual = document.querySelector('#manual');
const owner = form.dataset.owner === 'true';
const token = new URLSearchParams(location.hash.slice(1)).get('token');
let camera = null;
let decoder = null;
let submitting = false;
if (!owner && location.hash) history.replaceState(null, '', location.pathname);
if (owner) {
  button.disabled = true;
  fetch('/api/profiles').then(async response => {
    if (!response.ok) throw new Error('Войди в панель Torsher и открой эту страницу снова.');
    const data = await response.json();
    const select = form.elements.profile;
    select.add(new Option('Выбери отдельный профиль гостя', ''));
    for (const profile of data.items) select.add(new Option(profile.name, profile.id));
    button.disabled = false;
  }).catch(error => { status.textContent = error.message; });
} else if (!token) {
  status.textContent = 'Открой ссылку из приглашения. Если её нет, попроси владельца прислать новую.';
} else {
  button.disabled = false;
  browserButton.disabled = false;
  scanButton.disabled = false;
  scanButton.hidden = !navigator.mediaDevices?.getUserMedia;
  manual.open = scanButton.hidden;
}
function loadDecoder() {
  if (!decoder) {
    decoder = new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = '/activate-qr.js';
      script.onload = () => typeof window.jsQR === 'function' ? resolve(window.jsQR) : reject(new Error());
      script.onerror = reject;
      document.head.append(script);
    }).catch(error => { decoder = null; throw error; });
  }
  return decoder;
}
function stopCamera() {
  if (!camera) return;
  clearTimeout(camera.timer);
  camera.stream?.getTracks().forEach(track => track.stop());
  camera = null;
  video.srcObject = null;
  scanner.hidden = true;
  scanButton.disabled = false;
}
async function scanTv() {
  if (camera || submitting || !token) return;
  const session = { stream: null, timer: 0 };
  camera = session;
  scanButton.disabled = true;
  scanner.hidden = false;
  status.textContent = 'Наведи камеру на QR-код с телевизора.';
  function unavailable() {
    if (camera !== session) return;
    stopCamera();
    manual.open = true;
    status.textContent = 'Камера недоступна. Введи код с экрана телевизора вручную.';
  }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: false, video: { facingMode: { ideal: 'environment' } } });
    if (camera !== session) {
      stream.getTracks().forEach(track => track.stop());
      return;
    }
    session.stream = stream;
    stream.getVideoTracks().forEach(track => track.addEventListener('ended', unavailable, { once: true }));
    video.srcObject = stream;
    await video.play();
    const decode = await loadDecoder();
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d', { willReadFrequently: true });
    if (!context) throw new Error();

    function frame() {
      if (camera !== session) return;
      if (video.readyState >= 2 && video.videoWidth && video.videoHeight) {
        const scale = Math.min(1, 640 / Math.max(video.videoWidth, video.videoHeight));
        const width = Math.max(1, Math.round(video.videoWidth * scale));
        const height = Math.max(1, Math.round(video.videoHeight * scale));
        if (canvas.width !== width || canvas.height !== height) {
          canvas.width = width;
          canvas.height = height;
        }
        context.drawImage(video, 0, 0, width, height);
        const result = decode(context.getImageData(0, 0, width, height).data, width, height, { inversionAttempts: 'dontInvert' });
        const code = typeof result?.data === 'string' && /^torsher:tv:([A-HJ-NP-Z2-9]{6})$/.exec(result.data);
        if (code) {
          form.elements.code.value = code[1];
          void submit(false);
          return;
        }
      }
      session.timer = window.setTimeout(() => {
        try { frame(); } catch { unavailable(); }
      }, 180);
    }
    frame();
  } catch {
    unavailable();
  }
}
async function submit(browser) {
  if (submitting || (!owner && !token)) return;
  submitting = true;
  stopCamera();
  button.disabled = true;
  if (browserButton) browserButton.disabled = true;
  if (scanButton) scanButton.disabled = true;
  status.textContent = 'Проверяем…';
  const fields = new FormData(form);
  const body = owner
    ? { profileId: fields.get('profile'), name: fields.get('name') }
    : browser ? { token, browser: true } : { token, code: fields.get('code') };
  try {
    const response = await fetch(owner ? '/api/guest/invites' : '/api/guest/claim', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      status.textContent = response.status === 429 ? 'Слишком много попыток. Попробуй чуть позже.'
        : owner ? 'Ссылка не создана. Проверь выбранный профиль и вход в панель.'
        : browser ? 'Ссылка истекла или уже использована в другом браузере. Попроси владельца прислать новую.'
        : 'Код или приглашение уже недействительны. Проверь код на ТВ и при необходимости попроси новую ссылку.';
      return;
    }
    if (owner) {
      const data = await response.json();
      link.hidden = false;
      link.querySelector('input').value = data.url;
      status.textContent = 'Ссылка готова. Скопируй её и отправь гостю.';
    } else if (browser) {
      window.location.replace('/');
    } else {
      form.hidden = true;
      status.textContent = 'Телевизор подключён. Можно вернуться к ТВ.';
    }
  } catch {
    status.textContent = 'Сервер не ответил. Попробуй ещё раз.';
  } finally {
    submitting = false;
    button.disabled = false;
    if (browserButton) browserButton.disabled = false;
    if (scanButton) scanButton.disabled = false;
  }
}
form.addEventListener('submit', event => {
  event.preventDefault();
  void submit(false);
});
browserButton?.addEventListener('click', () => { void submit(true); });
scanButton?.addEventListener('click', () => { void scanTv(); });
document.querySelector('#stop-camera')?.addEventListener('click', () => {
  stopCamera();
  status.textContent = '';
  scanButton.focus();
});
document.addEventListener('visibilitychange', () => {
  if (document.hidden && camera) {
    stopCamera();
    status.textContent = '';
  }
});
window.addEventListener('pagehide', stopCamera);
`
