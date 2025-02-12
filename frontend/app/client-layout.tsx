"use client"

import { Header } from "@/components/Header"
import Footer from "@/components/Footer"
import { usePathname, redirect } from "next/navigation"
import { useEffect } from "react"

export default function ClientLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const pathname = usePathname()

  useEffect(() => {
    const token = localStorage.getItem("authToken")
    if(!token && pathname !== "/login") {
      redirect("/login")
    }
  }, [pathname])

  return (
    <div className="relative min-h-screen bg-gradient-to-br from-white to-orange-50">
      <div className="fixed inset-0 pointer-events-none z-0 flex justify-between">
        {/* Logo container'ları buraya */}
      </div>
      <div className="relative z-10">
        <main className="container mx-auto px-4 min-h-screen py-6 flex flex-col justify-center sm:py-12">
          {children}
        </main>
        <Footer />
      </div>
    </div>
  )
} 