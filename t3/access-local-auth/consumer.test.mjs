import { test } from 'node:test'
import assert from 'node:assert/strict'
import { retainedProbe, checkFacts, validationResponse } from './consumer.mjs'

test('a retained credential is verified online after its browser session was removed', async () => {
  const entries = new Map([['handle', { token: 'private-token', subject: 's', expires: Date.now() / 1000 + 60 }]])
  let calls = 0
  const result = await retainedProbe(entries, 'handle', async (entry) => {
    calls++
    assert.equal(entry.token, 'private-token')
    return { status: 403, online: true }
  })
  assert.equal(calls, 1)
  assert.equal(result.online, true)
  assert.equal(result.status, 403)
  assert.ok(result.remaining > 0)
  await assert.rejects(retainedProbe(entries, 'missing', async () => assert.fail()))
})

test('consumer rejects a successful HTTP response with wrong or expired identity facts', () => {
  const expected = { tenant: 't', client_id: 'c', audience: 'a', identity_origin: 'https://identity.test' }
  const facts = { tenant_id: 't', client_id: 'c', audience: 'a', issuer: 'https://identity.test/oidc',
    subject: 's', session_id: '11111111-1111-4111-8111-111111111111', expires_at: 200 }
  checkFacts(facts, expected, 's', 100)
  for (const key of ['tenant_id', 'client_id', 'audience', 'issuer', 'subject', 'session_id']) {
    assert.throws(() => checkFacts({ ...facts, [key]: 'wrong' }, expected, 's', 100))
  }
  assert.throws(() => checkFacts(facts, expected, 's', 200))
})


test('only a valid received Identity response can prove provider unavailability', async () => {
  const good = new Response(JSON.stringify({ code: 'identity_unavailable', correlation_id: '11111111-1111-4111-8111-111111111111' }), { status: 503, headers: { 'cache-control': 'no-store' } })
  const result = await validationResponse(good, {}, {}, 0)
  assert.equal(result.status, 503)
  assert.equal(result.identity_status, 503)
  for (const bad of [new Response('broken', { status: 503 }),
    new Response('{}', { status: 503, headers: { 'cache-control': 'no-store' } }),
    new Response('{}', { status: 200, headers: { 'cache-control': 'no-store' } })]) {
    await assert.rejects(validationResponse(bad, {}, {}, 0))
  }
})
