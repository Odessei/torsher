import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { eq } from 'drizzle-orm'
import { createApp } from '../app.ts'
import { ACCESS_TOKEN_COOKIE, DEVICE_TOKEN_COOKIE } from '../config.ts'
import { getDb, migrateDb } from '../db/index.ts'
import { devices, guestInvites } from '../db/schema.ts'
import { hashToken } from '../services/devices/index.ts'
import { createProfile, defaultProfile } from '../services/profiles/index.ts'
import { createOwner } from '../services/users/index.ts'
import { signToken } from '../utils/token.ts'

const host = 'guest.example.test'
const origin = `https://${host}`
const app = createApp()
let owner: Record<string, string>
let invited: ReturnType<typeof createProfile>

beforeAll(async () => {
  vi.stubEnv('TORSHER_GUEST_HOST', host)
  await migrateDb()
  const user = createOwner({ username: 'Guest test owner', passwordHash: 'x' })
  owner = { [ACCESS_TOKEN_COOKIE]: signToken(user.id, 'user_access') }
  invited = createProfile({
    name: 'Guest',
    color: 'blue',
    language: null,
    ageLimit: null,
    posterRatings: [],
  })
})

afterAll(async () => {
  await app.close()
  vi.unstubAllEnvs()
})

const guestHeaders = { host, origin }

describe('guest invitations', () => {
  it('separates the guest ingress from owner credentials and routes', async () => {
    expect((await app.inject({ url: '/api/health', headers: guestHeaders })).statusCode).toBe(200)
    expect((await app.inject({ method: 'HEAD', url: '/activate', headers: guestHeaders })).statusCode).toBe(200)
    expect((await app.inject({ method: 'HEAD', url: '/activate' })).statusCode).toBe(404)
    const invitation = await app.inject({ url: '/activate', headers: guestHeaders })
    expect(invitation.headers['permissions-policy']).toBe('camera=(self), microphone=()')
    const qr = await app.inject({ url: '/activate-qr.js', headers: guestHeaders })
    expect(qr.statusCode).toBe(200)
    expect(qr.headers['content-type']).toContain('text/javascript')
    expect(qr.headers['x-content-type-options']).toBe('nosniff')
    expect((await app.inject({ url: '/activate-qr.js' })).statusCode).toBe(404)
    for (const url of ['/panel/', '/api/overview', '/guest-invites', '/api/auth/setup', '/api/diagnostics/']) {
      expect((await app.inject({ url, headers: guestHeaders, cookies: owner })).statusCode).toBe(404)
    }
    expect((await app.inject({ url: '/api/profiles', headers: guestHeaders, cookies: owner })).statusCode).toBe(401)
    expect((await app.inject({ url: '/api/stream/no-access/0', headers: guestHeaders })).statusCode).toBe(401)
    expect((await app.inject({ url: '/api/hls/no-access/main.m3u8', headers: guestHeaders })).statusCode).toBe(401)
    expect((await app.inject({ url: '/guest-invites', cookies: owner })).statusCode).toBe(200)
    expect((await app.inject({ url: '/guest-invites' })).statusCode).toBe(401)
  })

  it('limits requests for the QR decoder without blocking a separate client', async () => {
    const qr = { url: '/activate-qr.js', headers: guestHeaders }
    const requests = await Promise.all(Array.from({ length: 31 }, () => app.inject({ ...qr, remoteAddress: '198.51.100.50' })))
    expect(requests.filter(response => response.statusCode === 200)).toHaveLength(30)
    expect(requests.filter(response => response.statusCode === 429)).toHaveLength(1)
    expect((await app.inject({ ...qr, remoteAddress: '198.51.100.51' })).statusCode).toBe(200)
  })

  it('claims exactly one TV for exactly one profile and supports owner revocation', async () => {
    const pending = await app.inject({
      method: 'POST',
      url: '/api/devices/pairing',
      headers: guestHeaders,
      payload: { type: 'tv' },
    })
    expect(pending.statusCode).toBe(201)
    const { code, secret } = pending.json()
    const privatePending = await app.inject({
      method: 'POST',
      url: '/api/devices/pairing',
      payload: { type: 'tv' },
    })
    const issued = await app.inject({
      method: 'POST',
      url: '/api/guest/invites',
      cookies: owner,
      payload: { name: 'Test television', profileId: invited.id },
    })
    expect(issued.statusCode).toBe(201)
    const link = new URL(issued.json().url)
    expect(link.origin).toBe(origin)
    expect(link.search).toBe('')
    expect((await app.inject({ url: '/activate', headers: guestHeaders })).statusCode).toBe(200)

    const token = new URLSearchParams(link.hash.slice(1)).get('token')
    const claim = (value: string, headers = guestHeaders) => app.inject({
      method: 'POST',
      url: '/api/guest/claim',
      headers,
      payload: { token, code: value },
    })
    expect((await claim(code, { host, origin: 'https://other.example.test' })).statusCode).toBe(403)
    expect((await claim(privatePending.json().code)).statusCode).toBe(404)
    const claimed = await Promise.all([claim(code), claim(code)])
    expect(claimed.map(response => response.statusCode).sort()).toEqual([204, 404])

    const pollUrl = `/api/devices/pairing/${secret}`
    expect((await app.inject({ url: pollUrl })).statusCode).toBe(404)
    const response = await app.inject({ url: pollUrl, headers: guestHeaders })
    expect(response.statusCode).toBe(200)
    expect(response.json().status).toBe('approved')
    expect(response.headers['set-cookie']).toContain('Secure')
    const cookies = { [DEVICE_TOKEN_COOKIE]: response.cookies[0]!.value }
    expect((await app.inject({ url: pollUrl, headers: guestHeaders })).statusCode).toBe(404)

    const profiles = await app.inject({ url: '/api/profiles', headers: guestHeaders, cookies })
    expect(profiles.statusCode).toBe(200)
    expect(profiles.json()).toMatchObject({ items: [{ id: invited.id }], currentId: invited.id, selected: true })
    expect((await app.inject({ url: '/api/profiles', cookies })).statusCode).toBe(401)
    expect((await app.inject({
      method: 'POST',
      url: `/api/profiles/${defaultProfile().id}/select`,
      headers: guestHeaders,
      cookies,
      payload: {},
    })).statusCode).toBe(404)
    expect((await app.inject({
      method: 'POST',
      url: '/api/devices/pairing/confirm',
      headers: guestHeaders,
      cookies: owner,
      payload: { name: 'Other', code },
    })).statusCode).toBe(404)
    expect((await app.inject({
      method: 'DELETE',
      url: `/api/devices/${response.json().device.id}`,
      cookies: owner,
    })).statusCode).toBe(200)
    expect((await app.inject({ url: '/api/profiles', headers: guestHeaders, cookies })).statusCode).toBe(401)
  })

  it('rejects an expired invitation and limits guesses per invitation', async () => {
    const issue = async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api/guest/invites',
        cookies: owner,
        payload: { name: 'Test television', profileId: invited.id },
      })
      expect(response.statusCode).toBe(201)
      return new URLSearchParams(new URL(response.json().url).hash.slice(1)).get('token')!
    }
    const claim = (token: string, code: string) => app.inject({
      method: 'POST',
      url: '/api/guest/claim',
      headers: guestHeaders,
      payload: { token, code },
    })
    const pending = await app.inject({
      method: 'POST',
      url: '/api/devices/pairing',
      headers: guestHeaders,
      payload: { type: 'tv' },
    })
    expect(pending.statusCode).toBe(201)
    const expired = await issue()
    getDb().update(guestInvites).set({ expiresAt: new Date(0) }).where(eq(guestInvites.tokenHash, hashToken(expired))).run()
    expect((await claim(expired, pending.json().code)).statusCode).toBe(404)

    const valid = await issue()
    for (let attempt = 0; attempt < 8; attempt++)
      expect((await claim(valid, '!!!!!!')).statusCode).toBe(404)
    expect((await claim(valid, pending.json().code)).statusCode).toBe(429)
  })

  it('connects one browser and one TV to the same profile in either order', async () => {
    const issue = async () => {
      const r = await app.inject({
        method: 'POST',
        url: '/api/guest/invites',
        cookies: owner,
        payload: { name: 'Guest browser test', profileId: invited.id },
      })
      expect(r.statusCode).toBe(201)
      return new URLSearchParams(new URL(r.json().url).hash.slice(1)).get('token')!
    }
    const startTv = async () => {
      const r = await app.inject({
        method: 'POST',
        url: '/api/devices/pairing',
        headers: guestHeaders,
        payload: { type: 'tv' },
      })
      expect(r.statusCode).toBe(201)
      return r.json()
    }
    const claim = (payload: { token: string, browser: true } | { token: string, code: string }, headers = guestHeaders) => app.inject({
      method: 'POST',
      url: '/api/guest/claim',
      headers,
      payload,
      remoteAddress: '192.0.2.10',
    })
    const testProfile = async (cookies: Record<string, string>) => {
      const profiles = await app.inject({ url: '/api/profiles', headers: guestHeaders, cookies })
      expect(profiles.statusCode).toBe(200)
      expect(profiles.json()).toMatchObject({ items: [{ id: invited.id }], currentId: invited.id, selected: true })
      expect((await app.inject({ url: '/api/overview', headers: guestHeaders, cookies })).statusCode).toBe(404)
      expect((await app.inject({ url: '/api/profiles', cookies })).statusCode).toBe(401)
    }

    for (const browserFirst of [true, false]) {
      const token = await issue()
      const a = await startTv()
      const b = await startTv()
      const browser = () => claim({ token, browser: true })
      const tv = () => claim({ token, code: a.code })
      const pending = browserFirst ? await browser() : await tv()
      expect(pending.statusCode).toBe(204)
      expect((await (browserFirst ? browser() : claim({ token, code: b.code }))).statusCode).toBe(404)
      const second = browserFirst ? await tv() : await browser()
      expect(second.statusCode).toBe(204)
      expect((await browser()).statusCode).toBe(404)
      expect((await claim({ token, code: b.code })).statusCode).toBe(404)

      const browserReply = browserFirst ? pending : second
      expect(browserReply.headers['set-cookie']).toContain('Secure')
      expect(browserReply.headers['set-cookie']).toContain('HttpOnly')
      const browserToken = browserReply.cookies.find(cookie => cookie.name === DEVICE_TOKEN_COOKIE)!.value
      const browserCookies = { [DEVICE_TOKEN_COOKIE]: browserToken }
      await testProfile(browserCookies)
      const tvReply = await app.inject({ url: `/api/devices/pairing/${a.secret}`, headers: guestHeaders })
      expect(tvReply.statusCode).toBe(200)
      const tvCookies = { [DEVICE_TOKEN_COOKIE]: tvReply.cookies[0]!.value }
      await testProfile(tvCookies)

      const device = getDb().select().from(devices).where(eq(devices.tokenHash, hashToken(browserToken))).get()!
      expect(device.type).toBe('browser')
      expect((await app.inject({
        method: 'DELETE',
        url: `/api/devices/${device.id}`,
        cookies: owner,
      })).statusCode).toBe(200)
      expect((await app.inject({ url: '/api/profiles', headers: guestHeaders, cookies: browserCookies })).statusCode).toBe(401)
      await testProfile(tvCookies)
    }
  })
})
