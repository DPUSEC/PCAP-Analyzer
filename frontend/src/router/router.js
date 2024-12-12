// src/router/index.js
import { createRouter, createWebHistory } from 'vue-router'
// Bileşenlerin doğru konumda olduğundan emin olun
import StartPage from '../components/StartPage.vue' 
import LoginPage from '../components/LoginPage.vue'
import SignupPage from '@/components/SignupPage.vue'
import ForgotPasswordPage from '@/components/ForgotPasswordPage'
import DashboardPage from '@/components/DashboardPage.vue'

const routes = [
  {
    path: '/',
    name: 'StartPage',
    component: StartPage
  },
  {
    path: '/login',
    name: 'LoginPage',
    component: LoginPage
  },
  {
    path: '/signup', // Yeni rota
    name: 'SignupPage',
    component: SignupPage,
  },
  {
    path: '/forgot-password',
    name: 'forgot-password',
    component: ForgotPasswordPage, // Şifre sıfırlama sayfasını buraya ekliyoruz
  },
  {
    path: '/dashboard',
    name: 'Dashboard',
    component: DashboardPage,
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
