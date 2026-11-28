export function guestPage(owner: boolean) {
  const heading = 'Приглашение в Torsher'
  const instructions = owner
    ? 'Ссылка действует 24 часа. По ней можно подключить один браузер и один телевизор к выбранному профилю.'
    : 'Смотри в браузере на этом устройстве или подключи телевизор по коду с экрана.'
  const fields = owner
    ? '<label>Профиль<select name="profile" required></select></label><label>Имя гостя<input name="name" maxlength="80" required placeholder="Например, Анна"></label>'
    : '<label>Код с телевизора<input name="code" maxlength="12" autocapitalize="characters" autocomplete="off" required placeholder="ABC-234"></label>'
  const action = owner ? 'Создать ссылку' : 'Подключить телевизор'
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${heading} · Torsher</title><style nonce="GUEST_NONCE">
[hidden]{display:none!important}*{box-sizing:border-box}body{margin:0;background:#111214;color:#f5f5f5;font:17px/1.5 system-ui,sans-serif}main{width:min(100% - 2rem,32rem);margin:clamp(1.5rem,8vw,5rem) auto}h1{line-height:1.15;font-size:clamp(1.7rem,7vw,2.5rem)}p{color:#c8cbd0}label{display:block;margin-block:1rem}input,select,button{display:block;width:100%;margin-top:.4rem;padding:.75rem;border:1px solid #666;border-radius:8px;font:inherit}input,select{background:#222;color:#fff}button{background:#f1c053;color:#19150b;font-weight:700;cursor:pointer}form[data-owner="false"]{border-top:1px solid #404247;margin-top:1.5rem;padding-top:.5rem}form[data-owner="false"] button{background:#222;color:#fff}button:disabled{opacity:.6}output{display:block;margin-top:1rem;min-height:1.5em}
</style></head><body><main><h1>${heading}</h1><p>${instructions}</p>
${owner ? '' : '<button id="browser" type="button" disabled>Смотреть в браузере</button>'}
<form id="setup" data-owner="${owner}">${fields}<button disabled>${action}</button></form>
<output id="status" aria-live="polite"></output>
<label id="link" hidden>Ссылка для гостя<input readonly autocomplete="off"></label>
</main><script src="${owner ? '/guest-invites.js' : '/activate.js'}" defer></script></body></html>`
}

export const guestPageScript = `
const form = document.querySelector('#setup');
const status = document.querySelector('#status');
const link = document.querySelector('#link');
const button = form.querySelector('button');
const browserButton = document.querySelector('#browser');
const owner = form.dataset.owner === 'true';
const token = new URLSearchParams(location.hash.slice(1)).get('token');
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
}
async function submit(browser) {
  button.disabled = true;
  if (browserButton) browserButton.disabled = true;
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
    button.disabled = false;
    if (browserButton) browserButton.disabled = false;
  }
}
form.addEventListener('submit', event => {
  event.preventDefault();
  void submit(false);
});
browserButton?.addEventListener('click', () => { void submit(true); });
`
