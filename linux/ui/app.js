(() => {
  'use strict';
  const token = location.hash.slice(1);
  const $ = selector => document.querySelector(selector);
  const status = $('#status');
  const message = $('#message');
  const connect = $('#connect');
  const remove = $('#remove');
  const input = $('#hostname');
  const api = async (path, body) => {
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST',
      credentials: 'omit',
      headers: {'X-PrivetDNS-Session': token, ...(body === undefined ? {} : {'Content-Type': 'application/json'})},
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw Error(data.error || 'Не удалось выполнить действие');
    return data;
  };
  const show = (text, error = false) => {
    message.textContent = text;
    message.classList.toggle('error', error);
    message.hidden = false;
  };
  const refresh = async () => {
    try {
      const data = await api('/api/status');
      status.className = `status ${data.installed ? data.healthy ? '' : 'error' : 'off'}`;
      status.textContent = data.installed ? data.healthy ? 'Подключено' : 'Требуется восстановление' : 'Не подключено';
      connect.disabled = data.installed;
      remove.disabled = !data.installed;
    } catch (error) {
      status.className = 'status error';
      status.textContent = 'Нет связи';
      show(error.message, true);
    }
  };
  $('#connect-form').addEventListener('submit', async event => {
    event.preventDefault();
    connect.disabled = true;
    message.hidden = true;
    try {
      const host = input.value.trim().toLowerCase().replace(/\.$/, '');
      const result = await api('/api/install', {host});
      input.value = '';
      show(result.message || 'PrivetDNS подключён');
    } catch (error) {
      show(error.message, true);
    } finally {
      await refresh();
    }
  });
  remove.addEventListener('click', async () => {
    if (!confirm('Отключить PrivetDNS и вернуть прежний DNS?')) return;
    remove.disabled = true;
    message.hidden = true;
    try {
      const result = await api('/api/remove', {});
      show(result.message || 'Прежний DNS восстановлен');
    } catch (error) {
      show(error.message, true);
    } finally {
      await refresh();
    }
  });
  $('#reveal').addEventListener('click', () => {
    const visible = input.type === 'text';
    input.type = visible ? 'password' : 'text';
    $('#reveal').textContent = visible ? 'Показать' : 'Скрыть';
  });
  if (!/^[a-f0-9]{48}$/.test(token)) {
    show('Откройте адрес, который показан в терминале PrivetDNS Connect.', true);
    return;
  }
  refresh();
})();
