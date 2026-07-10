<script setup>
import { computed, onMounted, ref } from 'vue'
import { state, doLogout, bootstrap, loadEntries, loadKeysStatus, loadOrgKeys } from './store'
import Login from './components/Login.vue'
import PasswordPanel from './components/PasswordPanel.vue'
import KeyPanel from './components/KeyPanel.vue'
import AdminModal from './components/AdminModal.vue'
import ChangePwModal from './components/ChangePwModal.vue'
import WaitToast from './components/WaitToast.vue'
import DeleteConfirmModal from './components/DeleteConfirmModal.vue'

const loggedIn = computed(() => !!state.token)
const showAdmin = ref(false)
const showChangePw = ref(false)

async function enterApp() {
  await loadKeysStatus()
  if (state.currentTab === 'key') await loadOrgKeys()
  await loadEntries()
}

function switchTab(tab) {
  state.currentTab = tab
  if (tab === 'key') loadOrgKeys()
}

function onLogout() {
  doLogout()
  showAdmin.value = false
}

onMounted(async () => {
  const ok = await bootstrap()
  if (ok) await enterApp()
})

// 登录成功后由 Login 组件通知进入主界面
function onLoggedIn() {
  enterApp()
}
</script>

<template>
  <Login v-if="!loggedIn" @logged-in="onLoggedIn" />

  <div v-else class="app-wrap">
    <header class="topbar">
      <div class="brand">🔐 密码管理</div>
      <div class="spacer"></div>
      <span class="user">👤 {{ state.user }}{{ state.isAdmin ? '（管理员）' : '' }}</span>
      <button v-if="state.isAdmin" class="btn ghost" @click="showAdmin = true">⚙️ 管理</button>
      <button class="btn ghost" @click="showChangePw = true">🔑 修改密码</button>
      <button class="btn ghost" @click="onLogout">退出</button>
    </header>

    <main class="container">
      <nav class="tabs">
        <button class="tab" :class="{ active: state.currentTab === 'pw' }" @click="switchTab('pw')">🔑 密码</button>
        <button class="tab" :class="{ active: state.currentTab === 'key' }" @click="switchTab('key')">🔐 密钥库</button>
      </nav>

      <PasswordPanel v-show="state.currentTab === 'pw'" />
      <KeyPanel v-show="state.currentTab === 'key'" />
    </main>
  </div>

  <AdminModal v-if="showAdmin" @close="showAdmin = false" />
  <ChangePwModal v-if="showChangePw" @close="showChangePw = false" />

  <WaitToast />
  <DeleteConfirmModal />
</template>
