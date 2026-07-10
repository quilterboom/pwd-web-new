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
  // 两套数据都预加载，保证首次切换到任一标签都有数据
  await loadEntries()
  await loadOrgKeys()
}

function switchTab(tab) {
  state.currentTab = tab
  // 每次切换标签都重新向服务端请求对应数据（v-show 常驻挂载，不会因重挂载而自动拉取）
  if (tab === 'key') loadOrgKeys()
  else loadEntries()
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
