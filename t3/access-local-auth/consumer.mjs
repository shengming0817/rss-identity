// Disposable T3 wire consumer. ref: panva/openid-client src/index.ts@v6.8.8.
import https from 'node:https'
import http from 'node:http'
import { readFileSync, chmodSync } from 'node:fs'
import { randomBytes, randomUUID } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import * as oidc from 'openid-client'

const fail = () => { throw new Error('consumer_rejected') }
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
export function checkFacts(f, config, subject, now) {
  if (f.tenant_id !== config.tenant || f.client_id !== config.client_id || f.audience !== config.audience ||
      f.issuer !== config.identity_origin + '/oidc' || f.subject !== subject ||
      !uuid.test(f.session_id) || !Number.isSafeInteger(f.expires_at) || f.expires_at <= now) fail()
}

export async function retainedProbe(entries, handle, validate, binding) {
  const entry = entries.get(handle)
  if (!entry) fail()
  return { ...await validate(entry, binding), remaining: Math.floor(entry.expires - Date.now() / 1000) }
}

function cookie(req, name) {
  return (req.headers.cookie ?? '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))?.slice(name.length + 1)
}
function setCookie(res, name, value, age) {
  res.setHeader('Set-Cookie', `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${age}`)
}
function reply(res, status, body = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' })
  res.end(JSON.stringify(body))
}
async function body(req) {
  const parts = []; let size = 0
  for await (const chunk of req) { size += chunk.length; if (size > 32768) fail(); parts.push(chunk) }
  return Buffer.concat(parts).toString()
}

async function main() {
  const config = JSON.parse(readFileSync('/run/test/public.json'))
  const ca = readFileSync('/run/test/ca.pem')
  const entries = new Map(), sessions = new Map(), flows = new Map()
  const origin = new URL(config.identity_origin)
  const validationSecret = readFileSync('/run/test/validation-secret', 'utf8')
  // Physical endpoints are fixed by this fixture; URL, Host, SNI and certificate identity stay canonical.
  function request(url, options = {}, privatePath = false) {
    const logical = new URL(url)
    if (logical.origin !== origin.origin || (privatePath ? logical.pathname !== '/internal/v1/identity/validate' : !logical.pathname.startsWith('/oidc/'))) fail()
    return new Promise((resolve, reject) => {
      const req = https.request({ hostname: privatePath ? 'private-gateway' : 'public-gateway',
        port: privatePath ? 443 : 8443, servername: origin.hostname, ca,
        path: logical.pathname + logical.search, method: options.method ?? 'GET',
        headers: { ...Object.fromEntries(new Headers(options.headers)), host: origin.host },
        signal: options.signal, timeout: 10000 }, async res => {
        try {
          const text = await body(res)
          resolve(new Response(text || null, { status: res.statusCode, headers: res.headers }))
        } catch { reject(new Error('transport_unavailable')) }
      })
      req.on('timeout', () => req.destroy(new Error('timeout')))
      req.on('error', () => reject(new Error('transport_unavailable')))
      if (options.body) req.write(typeof options.body === 'string' ? options.body : options.body.toString())
      req.end()
    })
  }
  const client = await oidc.discovery(new URL(config.identity_origin + '/oidc'), config.client_id,
    { id_token_signed_response_alg: 'RS256' },
    oidc.ClientSecretBasic(readFileSync('/run/test/oidc-secret', 'utf8')),
    { [oidc.customFetch]: request, execute: [oidc.enableNonRepudiationChecks], timeout: 10 })

  async function validate(entry, binding) {
    const started = Math.floor(Date.now() / 1000)
    try {
      const wrong = binding === 'client'
      const res = await request(config.identity_origin + '/internal/v1/identity/validate', {
        method: 'POST', headers: { 'Content-Type': 'application/json',
          Authorization: 'Basic ' + Buffer.from(config.client_id + ':' + (wrong ? 'invalid-validation-secret-00000000' : validationSecret)).toString('base64') },
        body: JSON.stringify({ credential: entry.token,
          tenant_id: binding === 'tenant' ? '22222222-2222-4222-8222-222222222222' : config.tenant,
          audience: binding === 'audience' ? 'wrong-audience' : config.audience }) }, true)
      const data = await res.json()
      if (res.headers.get('cache-control') !== 'no-store') fail()
      if (res.status === 200) {
        const now = Math.floor(Date.now() / 1000)
        if (now < started) fail()
        checkFacts(data, config, entry.subject, now)
        return { status: 200, online: true, session_id: data.session_id }
      }
      const codes = { malformed_request: 400, invalid_client: 401, invalid_credential: 401,
        identity_not_active: 403, rate_limited: 429, identity_unavailable: 503 }
      if (codes[data.code] !== res.status || !uuid.test(data.correlation_id)) fail()
      return { status: res.status, online: true, correlation_id: data.correlation_id }
    } catch { return { status: 503, online: true } }
  }

  const server = https.createServer({ key: readFileSync('/run/test/product.key'), cert: readFileSync('/run/test/product.pem') }, async (req, res) => {
    try {
      const url = new URL(req.url, config.product_origin)
      if (req.headers.host !== new URL(config.product_origin).host || req.method !== 'GET') return reply(res, 400)
      if (url.pathname === '/') { res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' }); return res.end('<a href="/auth/login">登录产品</a>') }
      if (url.pathname === '/auth/login') {
        if (flows.size >= 128) fail()
        const id = randomBytes(32).toString('base64url'), state = oidc.randomState(), nonce = oidc.randomNonce()
        const verifier = oidc.randomPKCECodeVerifier()
        flows.set(id, { state, nonce, verifier, expires: Date.now() + 300000 })
        setCookie(res, '__Host-t32-flow', id, 300)
        const authorization = oidc.buildAuthorizationUrl(client, { redirect_uri: config.product_origin + '/auth/callback',
          scope: 'openid', audience: config.audience, state, nonce,
          code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256' })
        res.writeHead(303, { Location: authorization.href, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' })
        return res.end()
      }
      if (url.pathname === '/auth/callback') {
        const id = cookie(req, '__Host-t32-flow'), flow = flows.get(id)
        flows.delete(id) // Claim before any await, including failures and unknown token exchange results.
        if (!flow || flow.expires <= Date.now()) return reply(res, 401)
        const tokens = await oidc.authorizationCodeGrant(client, url, {
          expectedState: flow.state, expectedNonce: flow.nonce, pkceCodeVerifier: flow.verifier, idTokenExpected: true })
        const entry = { token: tokens.access_token, subject: tokens.claims().sub,
          expires: Math.floor(Date.now() / 1000) + tokens.expires_in }
        const result = await validate(entry)
        if (result.status !== 200 || entries.size >= 256) return reply(res, result.status === 200 ? 503 : result.status)
        const handle = randomUUID(), secret = randomBytes(32).toString('base64url')
        const old = cookie(req, '__Host-t32-product')
        if (old) sessions.delete(old)
        entries.set(handle, entry); sessions.set(secret, handle)
        setCookie(res, '__Host-t32-product', secret, tokens.expires_in)
        res.writeHead(303, { Location: '/app', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' })
        return res.end()
      }
      if (url.pathname === '/app') { res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' }); return res.end('<h1>产品会话已建立</h1>') }
      if (url.pathname === '/api/protected') {
        const secret = cookie(req, '__Host-t32-product'), handle = sessions.get(secret), entry = entries.get(handle)
        if (!entry) return reply(res, 401)
        const result = await validate(entry)
        if (result.status !== 200) { sessions.delete(secret); setCookie(res, '__Host-t32-product', '', 0) }
        return reply(res, result.status, result.status === 200 ? { handle, session_id: result.session_id } : {})
      }
      reply(res, 404)
    } catch { reply(res, 401) }
  })
  server.listen(443, '0.0.0.0')
  // Not an HTTP product route. Only the test controller mounts this private socket volume.
  const control = http.createServer(async (req, res) => {
    try {
      const input = JSON.parse(await body(req))
      if (req.method !== 'POST' || input.operation !== 'probe' || !['tenant', 'audience', 'client', undefined].includes(input.binding)) fail()
      reply(res, 200, await retainedProbe(entries, input.handle, validate, input.binding))
    } catch { reply(res, 400) }
  })
  control.listen('/control/consumer.sock', () => chmodSync('/control/consumer.sock', 0o600))
  const sweep = setInterval(() => {
    for (const [key, flow] of flows) if (flow.expires < Date.now()) flows.delete(key)
    for (const [key, entry] of entries) if (entry.expires + 600 < Date.now() / 1000) entries.delete(key)
    for (const [key, handle] of sessions) if (!entries.has(handle)) sessions.delete(key)
  }, 10000)
  process.on('SIGTERM', () => { clearInterval(sweep); server.closeAllConnections(); control.closeAllConnections(); server.close(); control.close() })
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main().catch(() => { console.error('consumer_start_failed'); process.exitCode = 1 })
