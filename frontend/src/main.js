import { createApp } from 'vue'
import App from './App.vue'
import router from './router/router'  // router.js dosyasını doğru yoldan import ediyoruz

const app = createApp(App)
app.use(router)
app.mount('#app')
