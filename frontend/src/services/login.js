// src/services/login.js

export async function login(username, password) {
    const response = await fetch("http://127.0.0.1:8000/api/v1/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password }),
    });
  
    if (!response.ok) {
      throw new Error("Login failed. Please check your credentials.");
    }
  
    const data = await response.json();
  
    // Token'ı localStorage'a kaydet
    localStorage.setItem("token", data.token);
  
    return data;
  }
  