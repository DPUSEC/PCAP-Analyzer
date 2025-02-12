import "./globals.css"
import { Inter } from "next/font/google"
import type { Metadata } from "next"
import { Header } from '@/components/Header'

const inter = Inter({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "DPUSEC PCAP Analyzer",
  description: "Analyze PCAP files with Suricata rules",
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="tr">
      <body>
        <Header />
        {children}
      </body>
    </html>
  )
}

