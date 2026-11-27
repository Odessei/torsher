<script setup lang="ts">
import type { PanelOption } from '../components/OptionsPanel.vue'
import { computed, nextTick, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppIcon from '../components/AppIcon.vue'
import AppRail from '../components/AppRail.vue'
import FocusSection from '../components/FocusSection.vue'
import OptionsPanel from '../components/OptionsPanel.vue'
import SpeedtestPanel from '../components/SpeedtestPanel.vue'
import {
  screensaverMinutes,
  setScreensaverMinutes,
} from '../composables/useScreensaver.ts'
import { useFocus } from '../focus/index.ts'
import { STREAM_BUFFER_OPTIONS } from '../lib/player.ts'
import { session, updatePlayerSettings } from '../session.ts'
import { SCREENSAVER_OPTIONS } from '../lib/screensaver.ts'

/**
 * Настройки витрины, как экран настроек у Apple TV: строки «название — значение»,
 * выбор в правой панели.
 */
const { t } = useI18n()
const focus = useFocus()

const RAIL_SECTION = 'rail-settings'

type Setting = 'screensaver' | 'speedtest' | 'streamBuffer'

const panel = ref<Setting>()
let panelOpener: HTMLElement | undefined

function screensaverLabel(minutes: number) {
  return minutes === 0
    ? t('settings.screensaverOff')
    : t('settings.screensaverAfter', { n: minutes })
}

const options = computed<PanelOption[]>(() =>
  SCREENSAVER_OPTIONS.map(minutes => ({
    id: String(minutes),
    label: screensaverLabel(minutes),
    selected: screensaverMinutes.value === minutes,
  })),
)

const streamBuffer = computed(
  () => session.profile?.player.streamBufferMinutes,
)
const bufferOptions = computed<PanelOption[]>(() =>
  STREAM_BUFFER_OPTIONS.map(minutes => ({
    id: String(minutes),
    label: t('player.settings.bufferMinutes', { minutes }),
    selected: minutes === streamBuffer.value,
  })),
)

function openPanel(id: Setting) {
  panelOpener = focus.current() ?? undefined
  panel.value = id
}

function closePanel() {
  panel.value = undefined

  nextTick(() => {
    if (panelOpener?.isConnected)
      focus.focusOn(panelOpener)
  })
}

function choose(id: string) {
  if (panel.value === 'streamBuffer') {
    void updatePlayerSettings({
      streamBufferMinutes: STREAM_BUFFER_OPTIONS.find(
        minutes => String(minutes) === id,
      ),
    })
  }
  else {
    setScreensaverMinutes(Number(id))
  }
  closePanel()
}
</script>

<template>
  <main class="screen settings">
    <h1 class="settings__title">
      {{ t("settings.title") }}
    </h1>

    <h2 class="settings__group">
      {{ t("settings.device") }}
    </h2>
    <p class="settings__note">
      {{ t("settings.deviceNote") }}
    </p>

    <FocusSection
      name="settings-list"
      class="settings__list"
      :edges="{ left: RAIL_SECTION }"
      autofocus
    >
      <button
        v-focusable
        class="setting"
        type="button"
        @click="openPanel('screensaver')"
      >
        <span class="setting__text">
          <span class="setting__name">{{ t("settings.screensaver") }}</span>
          <span class="setting__hint">{{ t("settings.screensaverHint") }}</span>
        </span>
        <span class="setting__value">
          {{ screensaverLabel(screensaverMinutes) }}
        </span>
        <AppIcon name="chevronRight" class="setting__chevron" />
      </button>
      <button
        v-focusable
        class="setting setting--connection"
        type="button"
        @click="openPanel('speedtest')"
      >
        <span class="setting__text">
          <span class="setting__name">{{ t("speedtest.title") }}</span>
          <span class="setting__hint">{{ t("speedtest.combinedHint") }}</span>
        </span>
        <AppIcon name="chevronRight" class="setting__chevron" />
      </button>
      <template v-if="streamBuffer !== undefined">
        <h2 class="settings__group settings__group--player">
          {{ t("settings.playerProfile") }}
        </h2>
        <button
          v-focusable
          class="setting"
          type="button"
          @click="openPanel('streamBuffer')"
        >
          <span class="setting__text">
            <span class="setting__name">{{
              t("player.settings.streamBuffer")
            }}</span>
            <span class="setting__hint">{{
              t("player.settings.streamBufferHint")
            }}</span>
          </span>
          <span class="setting__value">{{
            t("player.settings.bufferMinutes", { minutes: streamBuffer })
          }}</span>
          <AppIcon name="chevronRight" class="setting__chevron" />
        </button>
      </template>
    </FocusSection>

    <AppRail
      current="settings"
      :section="RAIL_SECTION"
      content="settings-list"
    />

    <SpeedtestPanel v-if="panel === 'speedtest'" @close="closePanel" />
    <OptionsPanel
      v-if="panel === 'screensaver'"
      :title="t('settings.screensaver')"
      :options="options"
      @select="choose"
      @close="closePanel"
    />
    <OptionsPanel
      v-if="panel === 'streamBuffer'"
      :title="t('player.settings.streamBuffer')"
      :options="bufferOptions"
      @select="choose"
      @close="closePanel"
    />
  </main>
</template>

<style scoped>
.settings {
  max-width: calc(var(--content-x) + var(--u) * 1200);
}

.settings__title {
  margin: 0 0 var(--space-5);
  font-size: var(--font-size-xl);
}

.settings__group {
  margin: 0;
  font-size: var(--font-size-m);
  font-weight: 600;
}

.settings__group--player {
  margin-top: var(--space-5);
}

.setting--connection {
  margin-top: var(--space-5);
}

.settings__note {
  margin: var(--space-1) 0 var(--space-3);
  color: var(--color-text-muted);
  font-size: var(--font-size-s);
}

/* Строка — фокус-язык строк: белая заливка с тёмным текстом */
.setting {
  display: flex;
  align-items: center;
  width: 100%;
  margin-bottom: var(--space-1);
  padding: calc(var(--u) * 22) calc(var(--u) * 28);
  border: 0;
  border-radius: calc(var(--u) * 16);
  background: var(--color-surface-raised);
  color: var(--color-text);
  font: inherit;
  text-align: left;
  transition: transform var(--motion-base) var(--motion-easing);
}

.setting:focus {
  --bump-scale: 1.02;

  background: var(--color-focus);
  color: var(--color-bg);
  transform: scale(var(--bump-scale));
}

.setting__text {
  display: flex;
  flex: 1;
  flex-direction: column;
  min-width: 0;
}

.setting__name {
  font-size: var(--font-size-m);
  font-weight: 600;
}

.setting__hint {
  margin-top: calc(var(--u) * 4);
  color: var(--color-text-muted);
  font-size: var(--font-size-s);
}

.setting__value {
  flex-shrink: 0;
  margin-left: var(--space-3);
  color: var(--color-text-muted);
  font-size: var(--font-size-m);
}

.setting__chevron {
  margin-left: calc(var(--u) * 12);
  font-size: calc(var(--u) * 32);
  color: var(--color-text-muted);
}

.setting:focus .setting__hint,
.setting:focus .setting__value,
.setting:focus .setting__chevron {
  color: var(--color-bg);
}
</style>
