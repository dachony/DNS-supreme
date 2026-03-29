<template>
  <div class="login-page">
    <div class="login-card">
      <h1>DNS Supreme</h1>
      <p class="subtitle">Sign in to your account</p>

      <div v-if="error" class="error-msg">{{ error }}</div>

      <!-- Login Form -->
      <form v-if="!mfaStep" @submit.prevent="handleLogin">
        <div class="field">
          <label>Username</label>
          <input v-model="username" type="text" placeholder="admin" autofocus />
        </div>
        <div class="field">
          <label>Password</label>
          <input v-model="password" type="password" placeholder="Password" />
        </div>
        <button type="submit" :disabled="loading" class="btn-login">
          {{ loading ? 'Signing in...' : 'Sign In' }}
        </button>
      </form>

      <!-- MFA Form -->
      <form v-else @submit.prevent="handleMFA">
        <p class="mfa-info">Enter the 6-digit code from your authenticator app</p>
        <div class="field">
          <label>MFA Code</label>
          <input v-model="mfaCode" type="text" placeholder="000000" maxlength="6"
            autofocus autocomplete="one-time-code" />
        </div>
        <button type="submit" :disabled="loading" class="btn-login">
          {{ loading ? 'Verifying...' : 'Verify' }}
        </button>
        <button type="button" @click="mfaStep = false; error = ''" class="btn-back">Back to login</button>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { login, verifyMFA } from '../auth'

const router = useRouter()
const username = ref('')
const password = ref('')
const mfaCode = ref('')
const mfaStep = ref(false)
const loading = ref(false)
const error = ref('')

async function handleLogin() {
  error.value = ''
  loading.value = true
  try {
    const result = await login(username.value, password.value)
    if (result.mfaRequired) {
      mfaStep.value = true
    } else {
      router.push('/')
    }
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Login failed'
  } finally {
    loading.value = false
  }
}

async function handleMFA() {
  error.value = ''
  loading.value = true
  try {
    await verifyMFA(mfaCode.value)
    router.push('/')
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Invalid code'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: var(--bg-body);
}
.login-card {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px;
  padding: 40px; width: 400px; max-width: 90vw;
}
.login-card h1 { color: #38bdf8; font-size: 1.8rem; margin-bottom: 4px; }
.subtitle { color: #64748b; font-size: 0.9rem; margin-bottom: 24px; }

.field { margin-bottom: 16px; }
.field label { display: block; color: #94a3b8; font-size: 0.85rem; margin-bottom: 6px; }
.field input {
  width: 100%; padding: 10px 14px; background: #0f172a; border: 1px solid #334155;
  border-radius: 8px; color: #e2e8f0; font-size: 1rem;
}
.field input::placeholder { color: #475569; }
.field input:focus { outline: none; border-color: #0ea5e9; }

.btn-login {
  width: 100%; padding: 12px; background: #0ea5e9; color: #fff; border: none;
  border-radius: 8px; font-size: 1rem; cursor: pointer; margin-top: 8px;
}
.btn-login:hover { background: #0284c7; }
.btn-login:disabled { opacity: 0.5; cursor: not-allowed; }

.btn-back {
  width: 100%; padding: 10px; background: transparent; color: #64748b;
  border: 1px solid #334155; border-radius: 8px; cursor: pointer; margin-top: 8px;
}

.error-msg {
  background: rgba(239,68,68,0.1); border: 1px solid #ef4444; color: #ef4444;
  padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 0.9rem;
}

.mfa-info { color: #94a3b8; font-size: 0.9rem; margin-bottom: 16px; }
</style>
