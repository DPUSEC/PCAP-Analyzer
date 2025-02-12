"use client"

import Link from "next/link"
import Image from "next/image"
import { usePathname } from "next/navigation"

export function Header() {
  const handleLogout = () => {
    localStorage.removeItem("authToken")
    window.location.href = "/login"
  }

  const pathname = usePathname()

  return (
    <header className="bg-white shadow-sm">
      <div className="container mx-auto px-4 py-4 flex justify-between items-center">
        <Link href="/" className="flex items-center gap-2">
          <Image
            src="/logo.png"
            alt="DPUSEC Logo"
            width={40}
            height={40}
            className="rounded-lg"
          />
          <h1 className="text-xl font-medium text-orange-600">DPUSEC PCAP Analyzer</h1>
        </Link>
        <div className="flex items-center gap-6">
          <nav className="flex gap-4">
            <Link
              href="/"
              className={`hover:text-orange-700 transition-colors ${pathname === '/' ? 'text-orange-600 font-semibold' : 'text-gray-600'}`}
            >
              Home Page
            </Link>
            <Link
              href="/about"
              className={`hover:text-orange-700 transition-colors ${pathname === '/about' ? 'text-orange-600 font-semibold' : 'text-gray-600'}`}
            >
              About-Us
            </Link>
          </nav>
          {
            localStorage.getItem("authToken") && (
              <button
                onClick={handleLogout}
                className="text-orange-600 hover:text-orange-800 font-medium transition-colors"
              >Log out
              </button>
            )
          }
        </div>
      </div>
    </header>
  )
}

