<script setup>
import { onMounted, ref } from 'vue'
import { api, showToast } from '../store'
import { algoBadge, fmtTime, HISTORY_ACTION_LABELS, humanizeComment } from '../utils'

const props = defineProps({ id: { type: Number, required: true } })
const emit = defineEmits(['close'])

const rows = ref([])

onMounted(async () => {
  try {
    rows.value = await api('/api/passwords/' + props.id + '/history')
  } catch (e) {
    showToast('加载失败：' + e.message)
  }
})
</script>

<template>
  <div class="modal">
    <div class="modal-card wide">
      <button class="modal-close" type="button" aria-label="关闭" title="关闭" @click="emit('close')">✕</button>
      <h2>修改记录</h2>
      <table class="hist-table">
        <thead>
          <tr><th>时间</th><th>动作</th><th>账号</th><th>算法</th><th>操作人</th><th>说明</th></tr>
        </thead>
        <tbody>
          <tr v-for="r in rows" :key="r.id">
            <td>{{ fmtTime(r.changed_at) }}</td>
            <td :class="'act-' + r.action">{{ HISTORY_ACTION_LABELS[r.action] || r.action }}</td>
            <td>{{ r.username || '' }}</td>
            <td><span v-if="r.algorithm" class="badge" :class="algoBadge(r.algorithm).cls">{{ algoBadge(r.algorithm).label }}</span></td>
            <td>{{ r.changed_by || '' }}</td>
            <td>{{ humanizeComment(r.comment || '') }}</td>
          </tr>
          <tr v-if="!rows.length"><td colspan="6" style="color:#6b7280">暂无记录</td></tr>
        </tbody>
      </table>
      <div class="modal-actions">
        <button class="btn ghost" @click="emit('close')">关闭</button>
      </div>
    </div>
  </div>
</template>
