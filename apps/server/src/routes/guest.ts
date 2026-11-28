import type { FastifyReply } from 'fastify'
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod'
import { randomBytes } from 'node:crypto'
import { and, eq, gt, lte } from 'drizzle-orm'
import { z } from 'zod'
import { DEVICE_TOKEN_COOKIE, deviceCookieOptions } from '../config.ts'
import { getDb } from '../db/index.ts'
import { devicePairings, devices, guestInvites } from '../db/schema.ts'
import { requireOwner } from '../middleware/auth.ts'
import { guestHost, isGuestRequest } from '../middleware/guest.ts'
import { hashToken, normalizeCode } from '../services/devices/index.ts'
import { getProfile } from '../services/profiles/index.ts'
import { createRateLimiter } from '../utils/rateLimit.ts'
import { guestPage, guestPageScript } from './guestPage.ts'

const DAY = 24 * 60 * 60 * 1000
const CLAIM_WINDOW = 60 * 1000
const attemptsByIp = createRateLimiter({ limit: 20, windowMs: CLAIM_WINDOW })
const attemptsByInvite = createRateLimiter({ limit: 8, windowMs: CLAIM_WINDOW })
const inviteToken = z.string().regex(/^[\w-]{43}$/)

function page(reply: FastifyReply, owner: boolean) {
  const nonce = randomBytes(18).toString('base64')
  return reply.header('Cache-Control', 'no-store')
    .header('Referrer-Policy', 'no-referrer')
    .header('Content-Security-Policy', `default-src 'none'; script-src 'self'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`)
    .type('text/html; charset=utf-8')
    .send(guestPage(owner).replace('GUEST_NONCE', nonce))
}

function script(reply: FastifyReply) {
  return reply.header('Cache-Control', 'no-store')
    .header('X-Content-Type-Options', 'nosniff')
    .type('text/javascript; charset=utf-8')
    .send(guestPageScript)
}

export const guestRoutes: FastifyPluginAsyncZod = async (app) => {
  app.get('/activate', (request, reply) =>
    isGuestRequest(request) ? page(reply, false) : reply.code(404).send())
  app.get('/activate.js', (request, reply) =>
    isGuestRequest(request) ? script(reply) : reply.code(404).send())
  app.get('/guest-invites', { onRequest: requireOwner }, (_request, reply) =>
    guestHost() ? page(reply, true) : reply.code(404).send())
  app.get('/guest-invites.js', { onRequest: requireOwner }, (_request, reply) =>
    guestHost() ? script(reply) : reply.code(404).send())

  app.post('/api/guest/invites', {
    onRequest: requireOwner,
    schema: {
      body: z.object({ profileId: z.string().uuid(), name: z.string().trim().min(1).max(80) }),
    },
  }, (request, reply) => {
    const host = guestHost()
    const { profileId, name } = request.body
    if (!host || !getProfile(profileId))
      return reply.code(404).send({ message: 'Profile not found' })

    const token = randomBytes(32).toString('base64url')
    const db = getDb()
    const expiresAt = new Date(Date.now() + DAY)
    db.transaction((tx) => {
      tx.delete(guestInvites).where(lte(guestInvites.expiresAt, new Date())).run()
      tx.insert(guestInvites).values({ tokenHash: hashToken(token), profileId, name, expiresAt }).run()
    })
    return reply.code(201).header('Cache-Control', 'no-store').send({ url: `https://${host}/activate#token=${token}`, expiresAt })
  })

  app.post('/api/guest/claim', {
    async onRequest(request, reply) {
      if (!isGuestRequest(request))
        return reply.code(404).send()
      if (request.headers.origin !== `https://${guestHost()}`)
        return reply.code(403).send()
    },
    schema: {
      body: z.union([
        z.strictObject({ token: inviteToken, code: z.string().min(6).max(12) }),
        z.strictObject({ token: inviteToken, browser: z.literal(true) }),
      ]),
    },
  }, (request, reply) => {
    reply.header('Cache-Control', 'no-store')

    const claim = request.body
    const browser = 'browser' in claim
    const tokenHash = hashToken(claim.token)
    if (!attemptsByIp.hit(request.ip) || !attemptsByInvite.hit(tokenHash))
      return reply.code(429).send()
    const now = new Date()
    const claimed = getDb().transaction((tx) => {
      const invite = tx.select().from(guestInvites).where(and(eq(guestInvites.tokenHash, tokenHash), gt(guestInvites.expiresAt, now))).get()
      if (!invite || (browser ? invite.browserClaimed : invite.tvClaimed))
        return

      let deviceToken: string | undefined
      if (browser) {
        deviceToken = randomBytes(32).toString('base64url')
        tx.insert(devices).values({
          type: 'browser',
          name: `${invite.name} (браузер)`,
          tokenHash: hashToken(deviceToken),
          guestProfileId: invite.profileId,
          profileId: invite.profileId,
          lastIp: request.ip,
          userAgent: request.headers['user-agent']?.slice(0, 500),
        }).run()
      }
      else {
        const pairing = tx.select().from(devicePairings).where(and(
          eq(devicePairings.code, normalizeCode(claim.code)),
          eq(devicePairings.guest, true),
          eq(devicePairings.state, 'pending'),
          eq(devicePairings.type, 'tv'),
          gt(devicePairings.expiresAt, now),
        )).get()
        if (!pairing)
          return

        tx.update(devicePairings).set({
          state: 'approved',
          guestProfileId: invite.profileId,
          name: invite.name,
          expiresAt: new Date(now.getTime() + CLAIM_WINDOW),
        }).where(eq(devicePairings.id, pairing.id)).run()
      }

      const identity = eq(guestInvites.id, invite.id)
      if (invite.browserClaimed || invite.tvClaimed)
        tx.delete(guestInvites).where(identity).run()
      else
        tx.update(guestInvites).set(browser ? { browserClaimed: true } : { tvClaimed: true }).where(identity).run()
      return { deviceToken }
    }, { behavior: 'immediate' })
    if (!claimed)
      return reply.code(404).send()
    if (claimed.deviceToken)
      reply.setCookie(DEVICE_TOKEN_COOKIE, claimed.deviceToken, { ...deviceCookieOptions, secure: true })
    return reply.code(204).send()
  })
}
