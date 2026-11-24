import { createRouter, createWebHistory } from 'vue-router'

import LoginAlerts from '@/views/LoginAlerts.vue'
import Overview from '@/views/Overview.vue'
import WorkbenchView from '@/views/WorkbenchView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'overview', component: Overview },
    { path: '/login_alerts', name: 'login-alerts', component: LoginAlerts },
    { path: '/:moduleKey', name: 'module', component: WorkbenchView, props: true },
  ],
})

export default router
