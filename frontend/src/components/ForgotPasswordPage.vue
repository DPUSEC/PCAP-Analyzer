<template>
  <div class="forgot-password-container">
    <h2>Forgot Your Password?</h2>
    <form @submit.prevent="handlePasswordReset">
      <div class="form-group">
        <label for="email">Enter your email:</label>
        <input
          type="email"
          id="email"
          v-model="email"
          placeholder="Enter your email address"
          required
        />
      </div>
      <button type="submit">Reset Password</button>
    </form>
    <p v-if="errorMessage" class="error">{{ errorMessage }}</p>
    <p class="login-link">
      Remembered your password? <router-link to="/login">Go back to login</router-link>
    </p>
  </div>
</template>

<script>
export default {
  data() {
    return {
      email: '',
      errorMessage: '',
    };
  },
  methods: {
    async handlePasswordReset() {
      if (!this.email) {
        this.errorMessage = 'Please enter your email address.';
        return;
      }

      try {
        // Here, we send the password reset request to the API
        const response = await fetch('http://localhost:5000/api/reset-password', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ email: this.email }),
        });

        if (!response.ok) {
          throw new Error('Failed to reset password. Please check your email.');
        }

        const data = await response.json();
        console.log('Password reset email sent:', data);
        this.$router.push('/login'); // Redirect user to login page
      } catch (error) {
        this.errorMessage = error.message || 'An error occurred.';
      }
    },
  },
};
</script>

<style scoped>
.forgot-password-container {
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
  background-color: #4caf50; /* Green for reset button */
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}
button:hover {
  background-color: #45a049; /* Darker green when hovering */
}
.error {
  color: red;
  margin-top: 10px;
}
.login-link {
  margin-top: 15px;
}
.login-link a {
  color: #4caf50;
  text-decoration: none;
}
.login-link a:hover {
  text-decoration: underline;
}
</style>
