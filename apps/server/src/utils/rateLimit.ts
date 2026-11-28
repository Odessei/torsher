export interface RateLimiter {
  /** Засчитывает попытку; `false` — лимит окна исчерпан */
  hit: (key: string, now?: number) => boolean
  /** Лимит окна уже исчерпан; попытка не засчитывается */
  isLimited: (key: string, now?: number) => boolean
  /** Секунд до конца текущего окна; 0 — окна нет */
  retryAfter: (key: string, now?: number) => number
  reset: (key?: string) => void
}

/**
 * Лимит попыток в фиксированном окне, в памяти процесса: сервер один,
 * после перезапуска счётчики начинаются заново. Записи с прошедшим окном
 * удаляются при следующих попытках, поэтому память не растёт от разных ключей.
 */
export function createRateLimiter(options: {
  limit: number
  windowMs: number
}): RateLimiter {
  const windows = new Map<string, { startedAt: number, count: number }>()
  const maxKeys = 10_000
  const sweepInterval = Math.min(15_000, options.windowMs)
  let lastSweep = Number.NEGATIVE_INFINITY

  function active(startedAt: number, now: number) {
    return now >= startedAt && now - startedAt < options.windowMs
  }

  function sweep(now: number) {
    for (const [key, entry] of windows) {
      if (!active(entry.startedAt, now))
        windows.delete(key)
    }
  }

  function current(key: string, now: number) {
    const entry = windows.get(key)

    return entry && active(entry.startedAt, now) ? entry : undefined
  }

  return {
    hit(key, now = Date.now()) {
      if (now < lastSweep || now - lastSweep >= sweepInterval) {
        sweep(now)
        lastSweep = now
      }

      const entry = current(key, now)

      if (!entry) {
        if (!windows.has(key) && windows.size >= maxKeys)
          return false
        windows.set(key, { startedAt: now, count: 1 })
        return true
      }

      entry.count += 1

      return entry.count <= options.limit
    },
    isLimited(key, now = Date.now()) {
      return (current(key, now)?.count ?? 0) >= options.limit
    },
    retryAfter(key, now = Date.now()) {
      const entry = current(key, now)

      return entry
        ? Math.ceil((entry.startedAt + options.windowMs - now) / 1000)
        : 0
    },
    reset(key) {
      if (key === undefined) {
        windows.clear()
        lastSweep = Number.NEGATIVE_INFINITY
      }
      else {
        windows.delete(key)
      }
    },
  }
}
