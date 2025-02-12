"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { apiUrl } from "@/constants"

export default function LoginPage() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [isRegistering, setIsRegistering] = useState(false)
  const router = useRouter()

  useEffect(() => {
    const authToken = localStorage.getItem("authToken")
    if (authToken) {
      router.push("/")
    }
  }, [router])

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()

    const endpoint = isRegistering ? "/register" : "/login"
    fetch(apiUrl + endpoint, {
      method: "POST",
      body: JSON.stringify({
        "username": email,
        "password": password
      }),
      headers: {
        "Content-Type": "application/json"
      }
    })
    .then(async (response) => {
      const data = await response.json()
      if (!response.ok) {
        alert(data.message || "Bir hata oluştu!")
        return
      }
      
      if (response.status === 201) {
        alert("Kullanıcı başarıyla oluşturuldu! Giriş yapabilirsiniz.")
        setIsRegistering(false)
      } else if (response.status === 200) {
        localStorage.setItem("authToken", data.token)
        router.push("/")
      }
    })
    .catch((error) => {
      console.error("API Hatası:", error)
      alert("Sunucuyla bağlantı kurulamadı!")
    })
  }

  return (
    <div className="relative max-w-md mx-auto min-h-screen flex items-center">
      <div className="absolute inset-0 bg-gradient-to-r from-orange-400 to-orange-500 shadow-xl transform -skew-y-6 sm:skew-y-0 sm:-rotate-3 sm:rounded-3xl opacity-90"></div>
      <div className="relative px-4 py-10 bg-white shadow-xl sm:rounded-3xl sm:p-16 overflow-hidden w-full">
        {/* Flu Logo Arka Plan */}
        <div
          className="absolute inset-0 pointer-events-none z-0"
          style={{
            backgroundImage: 'url("/logo2.png")',
            backgroundPosition: "center",
            backgroundRepeat: "no-repeat",
            backgroundSize: "80%",
            opacity: 0.05,
            filter: "blur(3px)"
          }}
        />

        <div className="relative z-10">
          <h1 className="text-3xl font-bold text-gray-900 mb-8 text-center">
            {isRegistering ? "New User Registration" : "DPUSEC PCAP Analyzer"}
          </h1>
          <form onSubmit={handleLogin} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-700">Username</label>
              <input
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-orange-500 focus:ring-orange-500 text-black"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-orange-500 focus:ring-orange-500 text-black"
                required
              />
            </div>
            <button
              type="submit"
              className="w-full bg-gradient-to-r from-orange-500 to-orange-600 text-white font-bold py-2 px-4 rounded-md hover:opacity-90 transition-opacity"
            >
              {isRegistering ? "Register" : "Login"}
            </button>
          </form>

          <button
            type="button"
            onClick={() => setIsRegistering(!isRegistering)}
            className="w-full mt-4 text-orange-600 font-semibold py-2 px-4 rounded-md hover:bg-orange-50 transition-colors"
          >
            {isRegistering ? "Return login" : "Register"}
          </button>
        </div>
      </div>
    </div>
  )
} 