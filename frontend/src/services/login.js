// src/services/login.js

import config from "@/config";

export async function login(username, password) {
    const response = await fetch(config.apiDomain + "/api/v1/login", {
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
  