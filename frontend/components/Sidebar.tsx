import { Upload, Shield, FileUp, BarChart2 } from "lucide-react"

interface SidebarProps {
  activeTab: string
  setActiveTab: (tab: string) => void
}

export function Sidebar({ activeTab, setActiveTab }: SidebarProps) {
  const tabs = [
    { id: "upload", icon: Upload, label: "PCAP Yükle" },
    { id: "rules", icon: Shield, label: "Kurallar" },
    { id: "custom", icon: FileUp, label: "Özel Kural" },
    { id: "analysis", icon: BarChart2, label: "Analiz" },
  ]

  return (
    <nav className="bg-gray-800 text-white w-64 space-y-6 py-7 px-2">
      <div className="space-y-3">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center space-x-3 w-full px-4 py-2 rounded transition-colors ${
              activeTab === tab.id ? "bg-gray-700" : "hover:bg-gray-700"
            }`}
          >
            <tab.icon size={20} />
            <span>{tab.label}</span>
          </button>
        ))}
      </div>
    </nav>
  )
}

