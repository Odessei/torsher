import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod'
import { readFile } from 'node:fs/promises'
import { z } from 'zod'
import { config } from '../config.ts'
import { messageResponse } from '../dto/common.ts'
import { historyRange, overviewResponse } from '../dto/overview.ts'
import { requireOwner } from '../middleware/auth.ts'
import { getOverview } from '../services/overview/index.ts'

const quotaSnapshot = z.object({
  limitBytes: z.number().int().positive(),
  usedBytes: z.number().int().nonnegative(),
  sampledAt: z.number().int().positive(),
})

const quotaOverviewResponse = overviewResponse.extend({
  storage: overviewResponse.shape.storage.extend({
    accountQuota: z.literal(true).optional(),
  }),
})

async function readQuota(path: string) {
  try {
    const snapshot = quotaSnapshot.parse(
      JSON.parse(await readFile(path, 'utf8')),
    )
    const age = Date.now() / 1000 - snapshot.sampledAt
    if (age < -5 || age > 150)
      return null

    return {
      total: snapshot.limitBytes,
      free: Math.max(0, snapshot.limitBytes - snapshot.usedBytes),
    }
  }
  catch {
    return null
  }
}

export const overviewRoutes: FastifyPluginAsyncZod = async (app) => {
  app.addHook('onRequest', requireOwner)

  app.get(
    '',
    {
      schema: {
        operationId: 'getOverview',
        tags: ['Overview'],
        querystring: z.object({ range: historyRange.optional() }),
        response: { 200: quotaOverviewResponse, 401: messageResponse },
      },
    },
    async (request) => {
      const overview = await getOverview(request.query.range)
      const quotaFile = config.accountQuotaFile
      if (!quotaFile)
        return overview

      const quota = await readQuota(quotaFile)
      return {
        ...overview,
        storage: {
          ...overview.storage,
          accountQuota: true as const,
          total: quota?.total ?? null,
          free: quota?.free ?? null,
        },
      }
    },
  )
}
