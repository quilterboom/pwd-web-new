<script setup>
import { state } from '../store'
</script>

<template>
  <div v-if="state.toast.show" class="toast" :class="{ error: state.toast.error }">
    {{ state.toast.text }}
  </div>

  <div v-if="state.wait.show" class="wait" role="alert" aria-live="assertive">
    <div class="wait-card">
      <div class="spinner"></div>
      <p>{{ state.wait.text }}</p>
    </div>
  </div>
</template>
