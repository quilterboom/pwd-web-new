<script setup>
import { computed, onMounted, ref } from 'vue'
import { state, doLogout, bootstrap, loadEntries, loadKeysStatus, loadOrgKeys, can, startIdleMonitor } from './store'
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
  // 三类数据并行预加载，避免首个接口（密钥状态）拖慢密码列表就绪，
  // 否则首次登录立刻点「查看」时 state.entries 尚未填充，弹窗会显示全 —
  await Promise.all([loadKeysStatus(), loadEntries(), loadOrgKeys()])
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
  if (ok) {
    startIdleMonitor() // 恢复会话成功即启动空闲监听
    await enterApp()
  }
})

// 登录成功后由 Login 组件通知进入主界面
function onLoggedIn() {
  startIdleMonitor() // 登录成功即启动（或重置）空闲倒计时
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
      <button v-if="can('account.change_password')" class="btn ghost" @click="showChangePw = true">🔑 修改密码</button>
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
