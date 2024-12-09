<template>
  <div class="login-container">
    <h2>Login</h2>
    <form @submit.prevent="handleLogin">
      <div class="form-group">
        <label for="username">Username:</label>
        <input
          type="text"
          id="username"
          v-model="username"
          placeholder="Enter your username"
          required
        />
      </div>
      <div class="form-group">
        <label for="password">Password:</label>
        <input
          type="password"
          id="password"
          v-model="password"
          placeholder="Enter your password"
          required
        />
      </div>
      <button type="submit">Login</button>
    </form>
    <p v-if="errorMessage" class="error">{{ errorMessage }}</p>
    <p class="signup-link">
      Don't have an account? <router-link to="/signup">Create an account</router-link>
    </p>
    <p class="forgot-password-link">
      <router-link to="/forgot-password">Forgot your password?</router-link>
    </p>
  </div>
</template>

<script>
// login.js dosyasını import ediyoruz
import { login } from '@/services/login.js'; // services/login.js dosyasını import ettik

export default {
  data() {
    return {
      username: "",
      password: "",
      errorMessage: "",
    };
  },
  methods: {
    async handleLogin() {
      if (!this.username || !this.password) {
        this.errorMessage = "All fields are required.";
        return;
      }

      try {
        const data = await login(this.username, this.password);

        console.log("Login successful:", data);
        this.$router.push("/dashboard"); // Giriş başarılıysa yönlendir
      } catch (error) {
        this.errorMessage = error.message || "An error occurred.";
      }
    },
  },
};
</script>

<style scoped>
/* Stil kısmı değişmeden devam edebilir */
.login-container {
  max-width: 400px;
  margin: 50px auto;
  padding: 20px;
  border: 1px solid #ccc;
  border-radius: 8px;
  background: #f9f9f9;
  text-align: center;
}
.form-group {
  margin-bottom: 15px;
  text-align: left;
}
input {
  width: 100%;
  padding: 8px;
  margin-top: 5px;
  border: 1px solid #ccc;
  border-radius: 4px;
}
button {
  width: 100%;
  padding: 10px;
  background-color: #4caf50;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}
button:hover {
  background-color: #45a049;
}
.error {
  color: red;
  margin-top: 10px;
}
.signup-link {
  margin-top: 15px;
}
.signup-link a {
  color: #4caf50;
  text-decoration: none;
}
.signup-link a:hover {
  text-decoration: underline;
}

.forgot-password-link {
  margin-top: 15px;
}

.forgot-password-link a {
  color: #4caf50;
  text-decoration: none;
}

.forgot-password-link a:hover {
  text-decoration: underline;
}
</style>
