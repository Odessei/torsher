import { shallowRef } from 'vue'

const portraitPhone = '(max-width: 640px) and (orientation: portrait)'

export const phoneLayout = shallowRef(false)

export function initPhoneLayout(web: boolean) {
  if (!web || typeof window.matchMedia !== 'function')
    return

  const query = window.matchMedia(portraitPhone)
  const update = () => {
    phoneLayout.value = query.matches
    document.documentElement.classList.toggle('phone-layout', query.matches)
  }

  update()
  if (typeof query.addEventListener === 'function')
    query.addEventListener('change', update)
  else
    query.addListener(update)
}
