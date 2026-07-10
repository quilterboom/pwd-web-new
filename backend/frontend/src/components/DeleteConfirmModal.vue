<script setup>
import { computed, ref, watch } from 'vue'
import { state, confirmDelete, closeDelete } from '../store'

const step = ref(1) // 1: 风险提示  2: 输入验证码
const typed = ref('')

const target = computed(() => state.deleteTarget)

watch(target, (t) => {
  if (t) {
    step.value = 1
    typed.value = ''
  }
})

function nextStep() {
  if (!target.value) return
  step.value = 2
}

function onTyped() {
  // 仅用于启用/禁用按钮，无 side effect
}

async function doConfirm() {
  if (typed.value.trim() !== '确认删除') return
  await confirmDelete()
}

function cancel() {
  closeDelete()
}
</script>

<template>
  <!-- 第一步：风险提示 -->
  <div v-if="target && step === 1" class="modal">
    <div class="modal-card modal-card-narrow">
      <button class="modal-close" type="button" aria-label="关闭" title="关闭" @click="cancel">✕</button>
      <h2>确认删除</h2>
      <div class="del-warn">
        <p>你即将删除<span>{{ target.type === 'key' ? '密钥' : '账号' }}</span> <strong>{{ target.name }}</strong>。</p>
        <p class="muted">删除后将生成一条删除记录供管理员在「审计日志」中查看。此操作不可撤销。</p>
      </div>
      <div class="modal-actions">
        <button class="btn ghost" @click="cancel">取消</button>
        <button class="btn danger" @click="nextStep">确认，下一步</button>
      </div>
    </div>
  </div>

  <!-- 第二步：键入验证码 -->
  <div v-if="target && step === 2" class="modal">
    <div class="modal-card modal-card-narrow">
      <button class="modal-close" type="button" aria-label="关闭" title="关闭" @click="cancel">✕</button>
      <h2>输入验证码以删除</h2>
      <p>正在删除{{ target.type === 'key' ? '密钥' : '账号' }}：<strong>{{ target.name }}</strong></p>
      <p class="muted">请在下方输入框中键入 <code class="del-code">确认删除</code> 四个字，以完成删除。</p>
      <input
        v-model="typed"
        type="text"
        class="del-type-input"
        placeholder="在此输入：确认删除"
        autocomplete="off"
        @input="onTyped"
        @keyup.enter="doConfirm"
      />
      <p class="del-type-hint" :class="{ ok: typed.trim() === '确认删除' }">
        {{ typed && typed.trim() !== '确认删除' ? '输入内容不符，请键入「确认删除」' : '' }}
      </p>
      <div class="modal-actions">
        <button class="btn ghost" @click="cancel">取消</button>
        <button class="btn danger" :disabled="typed.trim() !== '确认删除'" @click="doConfirm">确认删除</button>
      </div>
    </div>
  </div>
</template>
