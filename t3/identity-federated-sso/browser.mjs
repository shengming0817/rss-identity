// Real browser against immutable product artifacts; all inputs are disposable fixture data.
// ref: microsoft/playwright v1.60.0 browserContext.ts and fetch.ts.
import { chromium, expect } from '@playwright/test'
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import process from 'node:process'
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)
const playwrightVersion = require('@playwright/test/package.json').version

const config = JSON.parse(readFileSync('/input/browser.json', 'utf8'))
const { origin, idp, product, tenants, password } = config
const checks = []
let stage = 'environment'
let step = 'start'
let browser
let sequence = 0
const contexts = []
const providers = []
const admins = []
function write(name, value) {
  writeFileSync(`/out/${name}.tmp`, JSON.stringify(value), { mode: 0o600 })
  renameSync(`/out/${name}.tmp`, `/out/${name}.json`)
}
function pass(name, observations = {}) {
  checks.push({ name, result: 'passed', ...observations })
  write('progress', { stage: name, result: 'passed' })
}
async function control(action, extra = {}) {
  step = 'control'
  const id = ++sequence
  write('request', { id, action, ...extra })
  const end = Date.now() + 180000
  while (Date.now() < end) {
    if (existsSync('/out/response.json')) {
      const response = JSON.parse(readFileSync('/out/response.json', 'utf8'))
      if (response.id === id) {
        if (response.error) throw new Error('control failed: ' + response.action)
        return response.value
      }
    }
    await new Promise(resolve => setTimeout(resolve, 100))
  }
  throw new Error('control timeout')
}
async function context() {
  const ctx = await browser.newContext({ locale: 'zh-CN' })
  ctx.setDefaultTimeout(15000)
  ctx.setDefaultNavigationTimeout(30000)
  contexts.push(ctx)
  // Static landing pages only: protocol APIs, callback, cookies and redirects remain real.
  // The product UI is packaged in the gateway but is not a prerequisite for this backend T3.
  await ctx.route(url => url.origin === origin && ['/login', '/consent', '/auth/resume', '/auth/error'].includes(url.pathname),
    route => route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>T33 protocol landing</title>' }))
  return ctx
}
async function platform(ctx, path, data, status = 200, csrf) {
  const headers = { Origin: origin, 'X-Identity-Request': '1' }
  if (csrf) headers['X-CSRF-Token'] = csrf
  const response = await ctx.request.fetch(`${origin}${path}`, { method: data === undefined ? 'GET' : 'POST',
    headers, data, maxRedirects: 0 })
  expect(response.status()).toBe(status)
  return response.json()
}
function credentials(index) {
  return { client_secret: config.providers[index].client_secret, ca_pem: readFileSync(config.ca_file, 'utf8') }
}
async function current(ctx, index) {
  step = 'central_session'
  const response = await ctx.request.get(`${origin}/api/v1/tenants/${tenants[index]}/session`)
  expect(response.status()).toBe(200)
  return response.json()
}
async function api(ctx, index, suffix, data, method = 'POST', status = 200) {
  step = 'identity_api'
  const headers = { Origin: origin, 'X-Identity-Request': '1' }
  if (suffix !== 'login') {
    const session = await ctx.request.get(`${origin}/api/v1/tenants/${tenants[index]}/session`)
    if (session.status() === 200) headers['X-CSRF-Token'] = (await session.json()).csrf_token
  }
  const response = await ctx.request.fetch(`${origin}/api/v1/tenants/${tenants[index]}/${suffix}`, {
    method, headers, data, maxRedirects: 0,
  })
  expect(response.status()).toBe(status)
  return status === 204 ? null : response.json()
}
async function local(ctx, index, login = 'admin') {
  return api(ctx, index, 'login', { login, password })
}
async function update(index, patch) {
  const p = providers[index]
  providers[index] = await api(admins[index], index, `providers/${p.id}`,
    { expected_version: p.version, settings: { ...p.settings, ...patch }, ...credentials(index) }, 'PUT')
}
async function enabled(index, value) {
  const p = providers[index]
  providers[index] = await api(admins[index], index, `providers/${p.id}/enabled`,
    { expected_version: p.version, enabled: value })
}
async function keycloak(page, user) {
  step = 'keycloak_form'
  await expect(page.locator('#username')).toBeVisible()
  await page.locator('#username').fill(user)
  await page.locator('#password').fill(password)
  await page.locator('#kc-login').click()
}
async function tenantSso(ctx, index, user = 'alice') {
  step = 'tenant_sso_api'
  const page = await ctx.newPage()
  await page.goto((await begin(ctx, index)).authorization_url)
  await keycloak(page, user)
  await expect(page).toHaveURL(origin + '/auth/resume')
  return { page, session: await current(ctx, index) }
}
async function downstream(ctx, index, page, kind) {
  step = 'downstream_' + kind
  const challenge = new URL(page.url()).searchParams.get(kind + '_challenge')
  expect(challenge).toBeTruthy()
  const headers = { Origin: origin, 'X-Identity-Request': '1' }
  const prepared = await ctx.request.post(`${origin}/api/v1/downstream/${kind}`, { headers, data: { challenge } })
  expect(prepared.status()).toBe(200)
  const flow = await prepared.json()
  expect(flow.tenant_id).toBe(tenants[index])
  return async () => {
    const session = await current(ctx, index)
    const accepted = await ctx.request.post(`${origin}/api/v1/downstream/${kind}/accept`, {
      headers: { ...headers, 'X-CSRF-Token': session.csrf_token }, data: { challenge, flow } })
    expect(accepted.status()).toBe(200)
    await page.goto((await accepted.json()).redirect_to)
  }
}
async function consumer(ctx, index, user = 'alice') {
  step = 'consumer_flow'
  const response = await ctx.request.post(`${product}/auth/login`, {
    headers: { Origin: product, 'X-T33-Request': '1' }, data: { client_id: config.clients[index].client_id },
  })
  expect(response.status()).toBe(200)
  const page = await ctx.newPage()
  await page.goto((await response.json()).authorization_url)
  await expect(page).toHaveURL(new RegExp(`${origin}/login`))
  const acceptLogin = await downstream(ctx, index, page, 'login')
  const existing = await ctx.request.get(`${origin}/api/v1/tenants/${tenants[index]}/session`)
  if (existing.status() !== 200) await tenantSso(ctx, index, user)
  await acceptLogin()
  await expect(page).toHaveURL(new RegExp(`${origin}/consent`))
  await (await downstream(ctx, index, page, 'consent'))()
  await expect(page).toHaveURL(product + '/session')
  const proof = await ctx.request.get(`${product}/session`)
  expect(proof.status()).toBe(200)
  const facts = await proof.json()
  expect(facts.tenant_id).toBe(tenants[index])
  expect(facts.client_id).toBe(config.clients[index].client_id)
  expect(facts.audience).toBe(config.clients[index].audience)
  expect(facts.issuer).toBe(origin + '/oidc')
  return { page, facts }
}
async function begin(ctx, index, suffix = 'login', fields = {}) {
  return api(ctx, index, `oidc/${providers[index].id}/${suffix}`,
    { client_id: 'identity-ui', return_target: 'resume', ...fields })
}
async function capture(ctx, authorization, user = 'alice') {
  step = 'callback_capture'
  const page = await ctx.newPage()
  let callback
  await page.route(`${origin}/api/v1/oidc/callback?**`, async route => {
    callback = route.request().url()
    await route.abort()
  })
  await page.goto(authorization).catch(() => {})
  if (!callback) await keycloak(page, user)
  await expect.poll(() => Boolean(callback), { timeout: 30000 }).toBe(true)
  await page.close()
  return callback
}
async function deliver(ctx, callback, success) {
  step = 'callback_delivery'
  const before = (await ctx.cookies(origin)).find(v => v.name === '__Host-identity-session')?.value
  const response = await ctx.request.get(callback, { maxRedirects: 0 })
  expect(response.status()).toBe(303)
  if (success) {
    expect(response.headers().location).toContain('/auth/resume')
    expect(response.headers()['set-cookie']).toContain('__Host-identity-session=')
  } else {
    expect(response.headers().location).toMatch(/\/auth\/error\?reason=(failed|unavailable|cancelled)$/)
    expect(response.headers()['set-cookie']).toBeUndefined()
    expect((await ctx.cookies(origin)).find(v => v.name === '__Host-identity-session')?.value).toBe(before)
  }
}
async function productStatus(ctx, status) {
  step = 'product_session'
  const response = await ctx.request.get(`${product}/session`)
  expect(response.status()).toBe(status)
  return response
}
async function restart(service, check) {
  await control('start', { service })
  await expect.poll(check, { timeout: 120000, intervals: [1000] }).toBe(true)
}

try {
  process.env.HOME = '/tmp/t33-browser-home'
  mkdirSync(`${process.env.HOME}/.pki/nssdb`, { recursive: true })
  execFileSync('certutil', ['-N', '-d', `sql:${process.env.HOME}/.pki/nssdb`, '--empty-password'])
  execFileSync('certutil', ['-A', '-d', `sql:${process.env.HOME}/.pki/nssdb`, '-n', 'T33 CA', '-t', 'C,,', '-i', config.ca_file])
  browser = await chromium.launch({ headless: true })
  const preflight = await context()
  await expect.poll(async () => {
    try { return (await preflight.request.get(`${origin}/oidc/.well-known/openid-configuration`)).status() === 200 }
    catch { return false }
  }, { timeout: 180000, intervals: [1000] }).toBe(true)
  const build = await preflight.request.get(`${origin}/identity-build.json`)
  expect((await build.json()).revision).toBe(config.ui_revision)
  expect(playwrightVersion).toBe(config.playwright)
  stage = 'platform_bootstrap'
  const owner = await context()
  const platformSession = await platform(owner, `/api/v1/tenants/${config.system_domain}/login`,
    { login: 'platform', password: config.platform_password })
  expect(platformSession.identity.principal_id).toBe(config.platform_admin)
  expect(platformSession.identity.platform_administrator).toBe(true)
  expect(platformSession.identity.administrator).toBe(false)
  const initial = await platform(owner, '/api/v1/platform/tenants')
  expect(initial.tenants).toEqual([])
  pass(stage, { system_domain: config.system_domain, principal_id: config.platform_admin })
  stage = 'tenant_api_onboarding'
  const created = await platform(owner, '/api/v1/platform/tenants', {
    tenant_id: tenants[0], name: 'T33 Alpha', administrator: { operation_id: config.operations[0],
      principal_id: config.admins[0], login: 'admin', password } }, 201, platformSession.csrf_token)
  expect(created.active).toBe(true)
  expect(created.operation).toMatchObject({ operation_id: config.operations[0], kind: 'tenant_created',
    tenant_id: tenants[0], principal_id: config.admins[0] })
  pass(stage, { ...created.operation })
  stage = 'tenant_cli_onboarding'
  const cli = await control('onboard_cli')
  expect(cli.active).toBe(true)
  expect(cli.operation).toMatchObject({ operation_id: config.operations[1], kind: 'tenant_created',
    tenant_id: tenants[1], principal_id: config.admins[1] })
  const registered = await platform(owner, '/api/v1/platform/tenants')
  expect(registered.tenants.map(t => t.tenant_id).sort()).toEqual([...tenants].sort())
  pass(stage, { ...cli.operation })
  for (let index = 0; index < 2; ++index) {
    step = `provider_${index}`
    const admin = await context(); admins.push(admin)
    const identity = await local(admin, index)
    expect(identity.identity.principal_id).toBe(config.admins[index])
    expect(identity.identity.administrator).toBe(true)
    expect(identity.identity.platform_administrator).toBe(false)
    const configured = config.providers[index]
    let p = await api(admin, index, 'providers', { settings: {
      issuer: configured.issuer, client_id: configured.client_id,
      redirect_uri: origin + '/api/v1/oidc/callback', scopes: ['openid', 'profile', 'email'],
      claims: { email: 'email', groups: null }, jit: true,
    }, ...credentials(index) }, 'POST', 201)
    providers.push(p)
    await enabled(index, true)
    const test = await api(admin, index, `providers/${p.id}/test`, {})
    expect(test.passed).toBe(true)
  }
  stage = 'platform_authorization'
  const forbidden = { tenant_id: '33333333-3333-4333-8333-333333333333', name: 'Forbidden',
    administrator: { operation_id: '33333333-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      principal_id: '33333333-bbbb-4bbb-8bbb-bbbbbbbbbbbb', login: 'intruder', password } }
  for (let index = 0; index < 2; ++index) {
    const session = await current(admins[index], index)
    await platform(admins[index], '/api/v1/platform/tenants', forbidden, 401, session.csrf_token)
    await platform(admins[index], `/api/v1/platform/tenants/${tenants[1 - index]}/administrators`,
      forbidden.administrator, 401, session.csrf_token)
    expect((await admins[index].request.get(`${origin}/api/v1/tenants/${tenants[1 - index]}/session`)).status()).toBe(401)
  }
  expect((await owner.request.get(`${origin}/api/v1/tenants/${tenants[0]}/session`)).status()).toBe(401)
  expect((await platform(owner, '/api/v1/platform/tenants')).tenants).toHaveLength(2)
  pass(stage, { rejected_status: 401, tenant_count: 2 })
  const localAccount = await api(admins[0], 0, 'accounts', { login: 'alice@example.test', password, role: 'member' }, 'POST', 201)

  stage = 'tenant_sso'
  const a = await context()
  const joined = await tenantSso(a, 0)
  const downstreamA = await consumer(a, 0)
  pass(stage, { tenant_id: tenants[0], session_id: downstreamA.facts.session_id, client_id: downstreamA.facts.client_id })
  stage = 'same_email'
  expect(joined.session.identity.principal_id).not.toBe(localAccount.principal_id)
  expect(joined.session.identity.administrator).toBe(false)
  pass(stage, { principal_id: joined.session.identity.principal_id, local_principal_id: localAccount.principal_id })
  stage = 'consumer_sso'
  const b = await context()
  const downstreamB = await consumer(b, 1)
  expect(downstreamB.facts.subject).not.toBe(downstreamA.facts.subject)
  pass(stage, { tenant_id: tenants[1], session_id: downstreamB.facts.session_id, client_id: downstreamB.facts.client_id })

  stage = 'browser_binding'
  const badA = await context(), badB = await context()
  const first = await capture(badA, (await begin(badA, 0)).authorization_url)
  await deliver(badB, first, false)
  pass(stage, { status: 303 })
  stage = 'callback_replay'
  const replay = await context()
  const once = await capture(replay, (await begin(replay, 0)).authorization_url)
  await deliver(replay, once, true)
  await deliver(replay, once, false)
  pass(stage, { status: 303 })
  stage = 'tenant_binding'
  const wrongTenant = await context()
  const wrong = await wrongTenant.request.post(`${origin}/api/v1/tenants/${tenants[1]}/oidc/${providers[0].id}/login`, {
    headers: { Origin: origin, 'X-Identity-Request': '1' }, data: { client_id: 'identity-ui', return_target: 'resume' },
  })
  expect(wrong.status()).toBe(401)
  pass(stage, { status: wrong.status() })
  stage = 'return_target'
  await api(wrongTenant, 0, `oidc/${providers[0].id}/login`, { client_id: 'identity-ui', return_target: 'https://evil.example.test' }, 'POST', 400)
  pass(stage, { status: 400 })

  stage = 'configuration_version'
  const version = await context()
  const inFlight = await capture(version, (await begin(version, 0)).authorization_url)
  await update(0, { jit: false })
  await deliver(version, inFlight, false)
  await productStatus(a, 401)
  pass(stage, { provider_id: providers[0].id, config_version: providers[0].version })
  stage = 'jit_disabled'
  const jitOff = await context()
  const fresh = await capture(jitOff, (await begin(jitOff, 0)).authorization_url, 'fresh')
  await deliver(jitOff, fresh, false)
  await update(0, { jit: true })
  pass(stage)

  // New credentials/configuration revoke old sessions; use a fresh live grant for disable/cleanup.
  const revoke = await context()
  const revokeFacts = (await consumer(revoke, 0)).facts

  stage = 'explicit_link'
  const link = await context()
  const original = await local(link, 0, 'alice@example.test')
  const oldCookies = await link.cookies(origin)
  await api(link, 0, `oidc/${providers[0].id}/link`, { client_id: 'identity-ui', return_target: 'resume', password: 'incorrect fixture password' }, 'POST', 403)
  const target = await begin(link, 0, 'link', { password })
  const linkCallback = await capture(link, target.authorization_url, 'linker')
  await deliver(link, linkCallback, true)
  const linked = await current(link, 0)
  expect(linked.identity.principal_id).toBe(localAccount.principal_id)
  expect(linked.session.id).not.toBe(original.session.id)
  const old = await context(); await old.addCookies(oldCookies)
  expect((await old.request.get(`${origin}/api/v1/tenants/${tenants[0]}/session`)).status()).toBe(401)
  pass(stage, { principal_id: linked.identity.principal_id, session_id: linked.session.id })
  stage = 'link_conflict'
  const conflict = await context(); await local(conflict, 0)
  const conflictCallback = await capture(conflict, (await begin(conflict, 0, 'link', { password })).authorization_url, 'linker')
  await deliver(conflict, conflictCallback, false)
  pass(stage)

  stage = 'downstream_binding'
  await productStatus(revoke, 200)
  const mismatched = await revoke.request.get(`${product}/session?client_id=${config.clients[1].client_id}`)
  expect(mismatched.status()).toBe(401)
  const wrongAudience = await context()
  const prepare = await wrongAudience.request.post(`${product}/auth/login`, { headers: { Origin: product, 'X-T33-Request': '1' }, data: { client_id: config.clients[0].client_id } })
  const authorization = new URL((await prepare.json()).authorization_url)
  authorization.searchParams.set('audience', 'unregistered-api')
  const rejectedAudience = await wrongAudience.request.get(authorization.href, { maxRedirects: 0 })
  expect([400, 302, 303]).toContain(rejectedAudience.status())
  if (rejectedAudience.status() !== 400) expect(new URL(rejectedAudience.headers().location, origin).searchParams.has('error')).toBe(true)
  pass(stage, { cross_client_status: mismatched.status(), audience_status: rejectedAudience.status() })

  stage = 'central_logout'
  const logout = await context(); await consumer(logout, 1)
  await api(logout, 1, 'session/logout', undefined, 'POST', 204)
  await productStatus(logout, 401)
  pass(stage)
  stage = 'configuration_disabled'
  const disabled = await context()
  const disabledCallback = await capture(disabled, (await begin(disabled, 0)).authorization_url)
  const cleanupTarget = await control('cleanup_snapshot', { session_id: revokeFacts.session_id })
  expect(cleanupTarget.grants.length).toBeGreaterThan(0)
  await enabled(0, false)
  await deliver(disabled, disabledCallback, false)
  pass(stage, { provider_id: providers[0].id, config_version: providers[0].version })
  stage = 'provider_revocation'
  expect((await revoke.request.get(`${origin}/api/v1/tenants/${tenants[0]}/session`)).status()).toBe(401)
  await productStatus(revoke, 401)
  await enabled(0, true)
  await productStatus(revoke, 401)
  pass(stage)

  stage = 'keycloak_unavailable'
  await control('stop', { service: 'keycloak' })
  const unavailable = await context()
  await api(unavailable, 0, `oidc/${providers[0].id}/login`, { client_id: 'identity-ui', return_target: 'resume' }, 'POST', 503)
  await restart('keycloak', async () => {
    try { return (await preflight.request.get(config.providers[0].issuer + '/.well-known/openid-configuration')).status() === 200 }
    catch { return false }
  })
  await productStatus(a, 401)
  pass(stage)
  // A late-created control session prevents token expiry from masquerading as an outage failure.
  const healthy = await context(); await consumer(healthy, 1)
  stage = 'hydra_unavailable'
  await control('stop', { service: 'hydra' })
  await productStatus(healthy, 503)
  await restart('hydra', async () => {
    try { return (await healthy.request.get(`${product}/session`)).status() === 200 }
    catch { return false }
  })
  await productStatus(a, 401)
  pass(stage)
  stage = 'validation_unavailable'
  await control('stop', { service: 'private-gateway' })
  await productStatus(healthy, 503)
  await restart('private-gateway', async () => {
    try { return (await healthy.request.get(`${product}/session`)).status() === 200 }
    catch { return false }
  })
  await productStatus(a, 401)
  pass(stage)

  stage = 'cleanup'
  const horizon = Math.max(...cleanupTarget.grants.map(g => g.horizon))
  let snapshot
  while (true) {
    snapshot = await control('cleanup_snapshot', { session_id: revokeFacts.session_id })
    if (snapshot.grants.length === 0 && cleanupTarget.grants.every(g => snapshot.cleaned.includes(g.id))) break
    if (snapshot.now > horizon + 120) throw new Error('cleanup deadline')
    await productStatus(revoke, 401)
    await new Promise(resolve => setTimeout(resolve, 5000))
  }
  await productStatus(a, 401)
  pass(stage, { grant_ids: cleanupTarget.grants.map(g => g.id), horizon, observed_at: snapshot.now })
  stage = 'events'
  const evidence = await control('events')
  const events = evidence.events
  for (const action of ['system_initialized', 'tenant_created', 'provider_created', 'provider_enabled', 'provider_updated', 'provider_disabled', 'jit_created', 'linked', 'created', 'active', 'revoking', 'cleaned']) {
    expect(events.some(e => e.action === action)).toBe(true)
  }
  expect(events.some(e => e.action === 'jit_created' && e.principal === joined.session.identity.principal_id && e.provider_id === providers[0].id)).toBe(true)
  expect(events.some(e => e.action === 'linked' && e.principal === localAccount.principal_id)).toBe(true)
  pass(stage, { actions: [...new Set(events.map(e => e.action))].sort(), count: events.length })
  write('result', { result: 'passed', checks, browser: browser.version(), playwright: playwrightVersion,
    providers: providers.map(p => ({ id: p.id, version: p.version, enabled: p.enabled })) })
} catch (error) {
  const location = String(error?.stack ?? '').match(/browser\.mjs:(\d+):(\d+)/)
  const assertion = {}
  for (const key of ['actual', 'expected']) {
    const value = error?.matcherResult?.[key]
    if (typeof value === 'number' || typeof value === 'boolean') assertion[key] = value
  }
  write('result', { result: 'failed', stage, step, failure: error?.name === 'TimeoutError' ? 'timeout' : 'assertion',
    source_line: location ? Number(location[1]) : null, assertion, checks })
  process.exitCode = 1
} finally {
  for (const ctx of contexts) await ctx.close().catch(() => {})
  await browser?.close()
}
