/**
 * Псевдолокаль для проверки вёрстки: строка длиннее на 40 % с лишним, буквы с
 * диакритикой, границы видны по скобкам — «[Śúbtítlés ẋẋẋẋ]». Только для
 * разработки: клиенты подключают её под dev-флагом, в сборку она не попадает.
 */

/** Знак добивки. По нему же тест сборки проверяет, что псевдолокали нет в бандле */
export const PSEUDO_PAD = 'ẋ'

const GROWTH = 0.4
const MIN_PAD = 2

// Только Latin-1: эти буквы есть в подмножестве шрифта витрины, ширина честная
const ACCENTS: Record<string, string> = {
  A: 'Å',
  C: 'Ç',
  E: 'É',
  I: 'Î',
  N: 'Ñ',
  O: 'Ö',
  U: 'Ü',
  Y: 'Ý',
  a: 'á',
  c: 'ç',
  e: 'é',
  i: 'í',
  n: 'ñ',
  o: 'ó',
  u: 'ú',
  y: 'ý',
}

function pseudoForm(form: string) {
  let visible = 0
  let offset = 0
  const parts: string[] = []

  function addText(part: string) {
    visible += part.length
    parts.push(part.replace(/[a-z]/gi, letter => ACCENTS[letter] ?? letter))
  }

  while (offset < form.length) {
    const start = form.indexOf('{', offset)
    const end = start < 0 ? -1 : form.indexOf('}', start + 1)
    if (end < 0)
      break
    addText(form.slice(offset, start))
    parts.push(form.slice(start, end + 1))
    offset = end + 1
  }
  addText(form.slice(offset))
  const pad = PSEUDO_PAD.repeat(Math.max(MIN_PAD, Math.ceil(visible * GROWTH)))

  return `[${parts.join('')} ${pad}]`
}

/** Псевдострока; формы множественного числа через ` | ` растягиваются каждая */
export function pseudoString(message: string) {
  return message.split(' | ').map(pseudoForm).join(' | ')
}

/** Тот же каталог строк, каждая строка — псевдо */
export function pseudoLocalize<T>(messages: T): T {
  if (typeof messages === 'string')
    return pseudoString(messages) as T

  if (Array.isArray(messages))
    return messages.map(pseudoLocalize) as T

  if (typeof messages === 'object' && messages !== null) {
    const result: Record<string, unknown> = {}

    for (const [key, value] of Object.entries(messages))
      result[key] = pseudoLocalize(value)

    return result as T
  }

  return messages
}
