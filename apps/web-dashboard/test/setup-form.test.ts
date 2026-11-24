import { it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createContext, runInContext } from 'node:vm';

const dashboardScript = readFileSync(new URL('../public/dashboard.js', import.meta.url), 'utf8');

// Exercise the real form submission code at the DOM and HTTP boundaries.
async function submitSetupForm(password: string, entries: Array<{ title: string; secret: string }>) {
  const requests: any[] = [];
  const messages: string[] = [];
  const fields: Record<string, { value: string; focus?: () => void }> = {
    'setup-vault-id': { value: 'form-test' },
    'setup-password': { value: password, focus() {} },
    'setup-recovery-mode': { value: 'RECOVERABLE' },
  };
  const rows = entries.map((entry, index) => ({
    dataset: { itemId: `entry-${index}`, category: 'Personal' },
    querySelector(selector: string) {
      return { value: selector === '.kv-key' ? entry.title : entry.secret };
    },
  }));
  const context = createContext({
    document: {
      addEventListener() {},
      getElementById(id: string) { return fields[id]; },
      querySelectorAll() { return rows; },
    },
    async fetch(url: string, options: { body: string }) {
      requests.push({ url, body: JSON.parse(options.body) });
      return { ok: true };
    },
    recordMessage(message: string) { messages.push(message); },
  });
  runInContext(dashboardScript, context);
  runInContext('showToast = recordMessage; closeModal = () => {}; fetchState = async () => {};', context);
  runInContext("setupVaultSnapshot = { vaultId: 'form-test', iv: 'loaded-vault-iv' };", context);
  await runInContext('executeSetup()', context);
  return { requests, messages };
}

it('submits newly entered secrets and the password without trimming their values', async () => {
  const password = '  Master Password  ';
  const secret = '  token="<value>&"  ';
  const { requests } = await submitSetupForm(password, [
    { title: 'Existing secret', secret: 'original' },
    { title: 'New secret', secret },
  ]);
  assert.strictEqual(requests.length, 1);
  assert.strictEqual(requests[0].url, '/api/vault/setup');
  assert.strictEqual(requests[0].body.password, password);
  assert.strictEqual(requests[0].body.items.length, 2);
  assert.strictEqual(requests[0].body.items[1].secret, secret);
  assert.strictEqual(requests[0].body.items[0].id, 'entry-0');
  assert.strictEqual(requests[0].body.expectedVaultIv, 'loaded-vault-iv');
});

it('submits an explicit empty list after all secret rows are cleared', async () => {
  const { requests } = await submitSetupForm('MasterPassword', [{ title: '', secret: '' }]);
  assert.deepEqual(requests[0].body.items, []);
});

it('keeps an empty password in the form and asks the user to enter one', async () => {
  const { requests, messages } = await submitSetupForm('', [{ title: 'Secret', secret: 'value' }]);
  assert.strictEqual(requests.length, 0);
  assert.match(messages[0], /Enter a master password/);
});

it('keeps the editor closed when the current vault cannot be loaded', async () => {
  let opened = false;
  const messages: string[] = [];
  const context = createContext({
    document: {
      addEventListener() {},
      getElementById() {
        return { classList: { contains() { return true; }, remove() { opened = true; } } };
      },
    },
    recordMessage(message: string) { messages.push(message); },
  });
  runInContext(dashboardScript, context);
  runInContext('showToast = recordMessage; fetchState = async () => null;', context);
  await runInContext('openSetupModal()', context);
  assert.strictEqual(opened, false);
  assert.match(messages[0], /Could not load the current vault/);
});
