<template>
  <div class="start">
    <img src="@/assets/vasak1.png" alt="Logo" class="logo" />
    <h1>Welcome</h1>
    <p>Click the button below to log in.</p>
    <button @click="goToLogin">Log In</button>
  </div>
</template>

<script>
export default {
  name: 'StartPage',
  methods: {
    goToLogin() {
      // Redirect to the /login page
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
img{
  width: 200px;
}
</style>
