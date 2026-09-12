// Chromium drives the candidate UI. All diagnostic output is an explicit allowlist.
import { chromium, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'
import http from 'node:http'
import readline from 'node:readline'
import assert from 'node:assert/strict'

const config = JSON.parse(readFileSync('/run/test/public.json'))
const input = readline.createInterface({ input: process.stdin })[Symbol.asyncIterator]()
async function rpc(operation, value = {}) {
  process.stdout.write(JSON.stringify({ operation, ...value }) + '\n')
  const line = await input.next()
  if (line.done) throw new Error('controller_unavailable')
  return JSON.parse(line.value)
}
const origin = config.identity_origin, product = config.product_origin
const base = `${origin}/api/v1/tenants/${config.tenant}`
const passwords = Object.fromEntries(['admin-password', 'member-password', 'new-password'].map(name => [name, readFileSync('/run/test/' + name, 'utf8')]))
const steps = {}, contexts = []
let stage = 'login', browser, admin
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
async function probe(handle, binding) {
  return new Promise((resolve, reject) => {
    const request = http.request({ socketPath: '/control/consumer.sock', path: '/', method: 'POST', timeout: 15000 }, async response => {
      const chunks = []
      for await (const chunk of response) chunks.push(chunk)
      if (response.statusCode !== 200) return reject(new Error('probe_rejected'))
      resolve(JSON.parse(Buffer.concat(chunks).toString()))
    })
    request.on('timeout', () => request.destroy(new Error('probe_timeout')))
    request.on('error', reject)
    request.end(JSON.stringify({ operation: 'probe', handle, binding }))
  })
}
async function context() {
  const ctx = await browser.newContext({ locale: 'zh-CN' })
  ctx.setDefaultTimeout(15000)
  contexts.push(ctx)
  return { ctx, page: await ctx.newPage() }
}
async function central(actor) {
  const response = await actor.ctx.request.get(base + '/session')
  assert.equal(response.status(), 200)
  return response.json()
}
async function api(actor, path, data, csrf, extra = {}) {
  return actor.ctx.request.post(base + '/' + path, { data, headers: {
    Origin: origin, 'X-Identity-Request': '1', ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...extra } })
}
async function login(name, password = passwords['member-password']) {
  const actor = await context()
  await actor.page.goto(`${origin}/tenants/${config.tenant}/login`)
  await actor.page.getByLabel('账户名', { exact: true }).fill(name)
  await actor.page.getByLabel('密码', { exact: true }).fill(password)
  await actor.page.getByRole('button', { name: '登录', exact: true }).click()
  await expect(actor.page.getByRole('heading', { name: '我的会话' })).toBeVisible()
  actor.session = await central(actor)
  return actor
}
async function create(name) {
  await admin.page.goto(`${origin}/tenants/${config.tenant}/accounts`)
  await admin.page.getByLabel('账户名', { exact: true }).fill(name)
  await admin.page.getByLabel('密码', { exact: true }).fill(passwords['member-password'])
  const response = admin.page.waitForResponse(r => r.url() === base + '/accounts' && r.request().method() === 'POST')
  await admin.page.getByRole('button', { name: '创建', exact: true }).click()
  const created = await response
  assert.equal(created.status(), 201)
  return (await created.json()).principal_id
}
async function handoff(actor) {
  const before = await sequence()
  await actor.page.goto(product + '/auth/login')
  for (let i = 0; i < 2; i++) {
    await actor.page.getByRole('button', { name: '继续', exact: true }).click()
  }
  await actor.page.waitForURL(product + '/app')
  const response = await actor.ctx.request.get(product + '/api/protected')
  assert.equal(response.status(), 200)
  actor.handle = (await response.json()).handle
  assert.equal((await probe(actor.handle)).status, 200)
  const active = (await rpc('events')).filter(e => e.seq > before && e.action === 'active')
  assert.equal(active.length, 1)
  actor.grant = active[0].grant_id
  return actor
}
async function event(action, field, value, after = 0) {
  const events = await rpc('events')
  const matching = events.filter(e => e.seq > after && e.action === action && e[field] === value)
  assert.equal(matching.length, 1)
  return matching[0]
}
async function sequence() {
  const events = await rpc('events')
  return events.at(-1)?.seq ?? 0
}
async function denied(actor, control) {
  const result = await probe(actor.handle)
  assert.ok([401, 403].includes(result.status))
  assert.equal(result.online, true)
  assert.ok(result.remaining > 0)
  const good = await probe(control.handle)
  assert.equal(good.status, 200)
  assert.ok([401, 403].includes((await actor.ctx.request.get(product + '/api/protected')).status()))
  // Re-probe after that failure cleared the browser's product cookie.
  const again = await probe(actor.handle)
  assert.ok([401, 403].includes(again.status))
  assert.equal(again.online, true)
  assert.ok(again.remaining > 0)
  return { status: again.status, online: true, remaining: again.remaining, control_status: good.status }
}
async function run(name, fn) {
  stage = name
  await rpc('stage', { stage })
  const value = await fn()
  steps[name] = { passed: true, ...value }
  await rpc('progress', { steps, browser_version: browser.version() })
}

try {
  browser = await chromium.launch({ headless: true })
  await run('login', async () => {
    admin = await login('admin', passwords['admin-password'])
    await event('initialized', 'principal', config.admin_principal)
    const principal = await create('member')
    globalThis.member = await handoff(await login('member'))
    member.principal = principal
    const cookies = await member.ctx.cookies()
    for (const name of ['__Host-identity-session', '__Host-identity-downstream-browser', '__Host-t32-product']) {
      const value = cookies.find(c => c.name === name)
      assert.ok(value && value.secure && value.httpOnly && value.sameSite === 'Lax' && value.path === '/')
      assert.equal(value.domain, name === '__Host-t32-product' ? 'product.t32.test' : 'identity.t32.test')
    }
    await event('created', 'session_id', member.session.session.id)
    await event('account_created', 'principal', principal)
    const storage = await member.page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) }))
    assert.deepEqual(storage, { local: [], session: [] })
  })
  await run('protection', async () => {
    const before = await sequence()
    const csrf = member.session.csrf_token
    for (const headers of [{ Origin: 'https://wrong.t32.test' }, { 'X-CSRF-Token': 'wrong' }]) {
      const response = await api(member, 'session/refresh', {}, csrf, headers)
      assert.equal(response.status(), 403)
      assert.equal(response.headers()['set-cookie'], undefined)
    }
    assert.equal((await api(member, 'accounts/' + member.principal + '/enabled', { enabled: false }, csrf)).status(), 403)
    assert.equal((await member.ctx.request.post(origin + '/internal/v1/identity/validate', { data: {} })).status(), 404)
    for (const binding of ['tenant', 'audience', 'client']) assert.ok([401, 403].includes((await probe(member.handle, binding)).status))
    const fresh = await context()
    const responses = []
    for (const login of ['missing-user', 'member']) {
      const response = await api(fresh, 'login', { login, password: 'deliberately incorrect password' })
      assert.equal(response.status(), 401)
      assert.equal(response.headers()['set-cookie'], undefined)
      responses.push(await response.json())
    }
    assert.deepEqual(responses[0], responses[1])
    assert.equal((await member.ctx.request.get(product + '/auth/callback?code=invalid&state=invalid')).status(), 401)
    const events = await rpc('events')
    assert.equal(events.filter(e => e.seq > before && e.principal === member.principal).length, 0)
  })
  await run('refresh', async () => {
    const old = (await member.ctx.cookies()).find(c => c.name === '__Host-identity-session')
    const response = await api(member, 'session/refresh', {}, member.session.csrf_token)
    assert.equal(response.status(), 200)
    const current = await response.json()
    assert.equal(current.session.id, member.session.session.id)
    assert.equal(current.session.absolute_expires_at, member.session.session.absolute_expires_at)
    assert.notEqual(current.csrf_token, member.session.csrf_token)
    assert.notEqual((await member.ctx.cookies()).find(c => c.name === old.name).value, old.value)
    const replay = await context()
    await replay.ctx.addCookies([old])
    assert.equal((await replay.ctx.request.get(base + '/session')).status(), 401)
    assert.equal((await member.ctx.request.get(product + '/api/protected')).status(), 200)
    member.session = current
    await event('refreshed', 'session_id', current.session.id)
  })
  await create('control')
  let control = await handoff(await login('control'))
  await run('logout', async () => {
    await member.page.goto(`${origin}/tenants/${config.tenant}/sessions`)
    await member.page.getByRole('button', { name: '退出当前会话', exact: true }).click()
    await expect(member.page.getByRole('heading', { name: '登录', exact: true })).toBeVisible()
    await event('revoked', 'session_id', member.session.session.id)
    return denied(member, control)
  })
  await run('logout_all', async () => {
    await create('all-user')
    const a = await handoff(await login('all-user')), b = await handoff(await login('all-user'))
    assert.equal((await api(a, 'sessions/logout-all', {}, a.session.csrf_token)).status(), 204)
    await event('all_revoked', 'session_id', a.session.session.id)
    await denied(a, control)
    return denied(b, control)
  })
  await run('password', async () => {
    const principal = await create('password-user')
    const actor = await handoff(await login('password-user'))
    assert.equal((await api(actor, 'account/password', { current_password: passwords['member-password'], password: passwords['new-password'] }, actor.session.csrf_token)).status(), 200)
    await event('password_changed', 'principal', principal)
    const result = await denied(actor, control)
    const fresh = await context()
    assert.equal((await api(fresh, 'login', { login: 'password-user', password: passwords['member-password'] })).status(), 401)
    await login('password-user', passwords['new-password'])
    return result
  })
  await run('disable', async () => {
    const principal = await create('disable-user')
    const actor = await handoff(await login('disable-user'))
    const row = admin.page.getByRole('row').filter({ hasText: 'disable-user' })
    await row.getByRole('button', { name: '停用账户', exact: true }).click()
    await admin.page.getByRole('alertdialog').getByRole('button', { name: '确认', exact: true }).click()
    await expect(row).toContainText('已停用')
    await event('account_disabled', 'principal', principal)
    await denied(actor, control)
    const fresh = await context()
    assert.equal((await api(fresh, 'login', { login: 'disable-user', password: passwords['member-password'] })).status(), 401)
    await row.getByRole('button', { name: '启用账户', exact: true }).click()
    await admin.page.getByRole('alertdialog').getByRole('button', { name: '确认', exact: true }).click()
    await expect(row).toContainText('已启用')
    await event('account_enabled', 'principal', principal)
    await login('disable-user')
    return denied(actor, control)
  })
  await run('storage_failure', async () => {
    await create('storage-user')
    const actor = await handoff(await login('storage-user'))
    await rpc('fault', { service: 'postgres', action: 'pause' })
    try {
      const unavailable = await probe(actor.handle)
      assert.equal(unavailable.status, 503)
      assert.equal(unavailable.identity_status, 503)
      assert.equal(unavailable.online, true)
      const fresh = await context()
      const response = await api(fresh, 'login', { login: 'storage-user', password: passwords['member-password'] })
      assert.equal(response.status(), 503)
      assert.equal(response.headers()['set-cookie'], undefined)
    } finally { await rpc('fault', { service: 'postgres', action: 'unpause' }) }
    assert.equal((await probe(actor.handle)).status, 200)
  })
  await run('cleanup_failure', async () => {
    await create('fault-user')
    const actor = await handoff(await login('fault-user'))
    control = await handoff(await login('control'))
    const before = await sequence()
    await rpc('fault', { service: 'hydra', action: 'pause' })
    try {
      const unavailable = await probe(actor.handle)
      assert.equal(unavailable.status, 503)
      assert.equal(unavailable.identity_status, 503)
      assert.equal(unavailable.online, true)
      assert.equal((await api(actor, 'session/logout', {}, actor.session.csrf_token)).status(), 204)
      await event('revoked', 'session_id', actor.session.session.id, before)
      // Wait for the production worker's actual pass; no internal test hooks.
      await sleep(45000)
      const events = await rpc('events')
      assert.ok(events.some(e => e.seq > before && e.action === 'revoking' && e.grant_id === actor.grant))
      assert.equal(events.filter(e => e.seq > before && e.action === 'cleaned' && e.grant_id === actor.grant).length, 0)
    } finally { await rpc('fault', { service: 'hydra', action: 'unpause' }) }
    const result = await denied(actor, control)
    let cleaned = false
    // Durable grant removal deliberately waits until the full protocol safety horizon.
    for (let i = 0; i < Math.ceil((config.grant_horizon_seconds + 90) / 5); i++) {
      const events = await rpc('events')
      if (events.some(e => e.seq > before && e.action === 'cleaned' && e.grant_id === actor.grant)) { cleaned = true; break }
      await sleep(5000)
    }
    assert.ok(cleaned)
    return result
  })
  await run('events', async () => {
    const events = await rpc('events')
    for (const action of ['initialized', 'account_created', 'created', 'refreshed', 'revoked', 'all_revoked',
      'password_changed', 'account_disabled', 'account_enabled', 'active', 'revoking', 'cleaned']) {
      assert.ok(events.some(e => e.action === action && e.tenant === config.tenant))
    }
    return { count: events.length }
  })
  await rpc('result', { steps, browser_version: browser.version() })
} catch (error) {
  const line = /scenario\.mjs:(\d+)/.exec(error?.stack ?? '')?.[1] ?? '0'
  await rpc('result', { stage, failure: (error?.name === 'TimeoutError' ? 'timeout_' : 'assertion_') + line })
  process.exitCode = 1
} finally {
  await browser?.close()
  process.stdin.destroy()
}
