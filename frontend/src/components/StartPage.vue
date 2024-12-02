<template>
  <div class="start">
    <h1>Hoşgeldiniz</h1>
    <p>Giriş yapmak için aşağıdaki butona tıklayın.</p>
    <button @click="goToLogin">Giriş Yap</button>
  </div>
</template>

<script>
export default {
  name: 'StartPage',
  methods: {
    goToLogin() {
      // /login sayfasına yönlendirme
      this.$router.push('/login');
    }
  }
}
</script>

<style scoped>
button {
  padding: 10px 20px;
  background-color: #4caf50;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}
button:hover {
  background-color: #45a049;
}
</style>
