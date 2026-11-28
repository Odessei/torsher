import type { FastifyReply, FastifyRequest } from 'fastify'
import process from 'node:process'

export function guestHost() {
  const host = process.env.TORSHER_GUEST_HOST?.trim().toLowerCase()
  return host && /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(host) ? host : undefined
}

export function isGuestRequest(request: FastifyRequest) {
  const host = guestHost()
  return !!host && request.headers.host?.toLowerCase() === host
}

// A new owner route is denied here by default, including the first-run routes.
const catalogOperations = new Set([
  'getHealth',
  'getAbout',
  'postDevicePairing',
  'getDevicePairing',
  'getProfiles',
  'postProfileSelect',
  'putCurrentPlayerSettings',
  'getHome',
  'getHomeContinue',
  'getHomeVideos',
  'getHomeVideo',
  'getCatalogBackdrops',
  'getCatalogDiscover',
  'getCatalogGenres',
  'getCatalogPerson',
  'getCatalogSearch',
  'getCatalogSeason',
  'getCatalogTitle',
  'getCatalogTitleExtras',
  'getCatalogTrending',
  'getTitleSources',
  'getTitleFiles',
  'getTitleLibrary',
  'getTitleProgress',
  'getTitleUpNext',
  'getTitleMine',
  'patchTitleMine',
  'postTitleOpen',
  'getTitleDownload',
  'getTorrentStats',
  'postPlayback',
  'getPlayback',
  'deletePlayback',
  'getViewingAttempt',
  'postPlaybackError',
  'putPlaybackPreferences',
  'putWatchState',
  'getPlaybackSubtitles',
  'postPlaybackSubtitleSearch',
  'postPlaybackSubtitleApply',
  'deletePlaybackSubtitle',
  'putPlaybackSubtitleOffset',
  'streamTorrentFile',
  'getDiagnostics',
  'postDiagnosticEvents',
  'getMine',
  'getMineItems',
  'getMineBootstrap',
  'getMineSectionCounts',
  'putMineStart',
  'getMineDiary',
  'getMineDiaryMonths',
  'postMineDiary',
  'patchMineDiaryEntry',
  'deleteMineDiaryEntry',
  'getMineOverview',
  'getMineTitlePersonal',
  'patchMineTitlePersonal',
  'putMineSeen',
  'postMineCycle',
  'patchMineCycle',
  'getMinePersonalContinue',
  'getMinePersonalWatched',
  'getMineRecommendations',
  'getMineRecommendationExclusions',
  'getSchedule',
  'getTitleFollow',
  'getFollowVoices',
  'getTitleAddonSources',
  'getHomeAddonRows',
  'postTitleAddonSourcePlay',
])

const guardedReadRoutes = new Set([
  '/api/img/:size/:file',
  '/api/hls/:id/main.m3u8',
  '/api/hls/:id/:segment',
  '/api/stream/addon/:id',
  '/api/library/files/:id/stream',
  '/api/library/files/:id/thumb',
])

export async function guestBoundary(request: FastifyRequest, reply: FastifyReply) {
  if (!isGuestRequest(request))
    return

  reply.header('Referrer-Policy', 'no-referrer')
  const read = request.method === 'GET' || request.method === 'HEAD'
  const path = request.url.split('?')[0]
  if (read && (
    path === '/' || path === '/activate' || path === '/activate.js'
    || /^\/(?:assets\/[\w.-]+|favicon\.(?:ico|svg)|apple-touch-icon\.png)$/.test(path)
  )) {
    return
  }

  if (request.method === 'POST' && path === '/api/guest/claim')
    return

  if (request.method === 'POST' && path === '/api/auth/refresh')
    return reply.code(401).serializer(JSON.stringify).send({ message: 'Unauthorized' })

  if (!read && request.headers.origin && request.headers.origin !== `https://${guestHost()}`)
    return reply.code(403).serializer(JSON.stringify).send({ message: 'Forbidden' })

  const operation = request.routeOptions.schema?.operationId
  if ((operation && catalogOperations.has(operation))
    || (read && guardedReadRoutes.has(request.routeOptions.url ?? ''))) {
    return
  }

  return reply.code(404).serializer(JSON.stringify).send({ message: 'Not found' })
}
