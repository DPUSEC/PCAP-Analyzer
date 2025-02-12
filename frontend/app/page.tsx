"use client"

import { useEffect, useState } from "react"
import { FileUpload } from "@/components/FileUpload"
import { RuleSelection } from "@/components/RuleSelection"
import { CustomRuleUpload } from "@/components/CustomRuleUpload"
import ClientLayout from "./client-layout"
import Link from 'next/link'
import { apiUrl } from "@/constants"
import LoadingScreen from "@/components/LoadingScreen"

export default function Home() {
  const [file, setFile] = useState<File | null>(null)
  const [selectedRules, setSelectedRules] = useState<Array<string>>([])
  const [analysisHistory, setAnalysisHistory] = useState<any[]>([])
  const [loading, setLoading] = useState<boolean>(false)
  const [currentPage, setCurrentPage] = useState<number>(1);
  const itemsPerPage = 10;

  useEffect(() => {
    fetch(apiUrl + "/analysis", {
      headers: {
        "Authorization": `Bearer ${localStorage.getItem("authToken")}`
      }
    })
      .then(async (response) => {
        if (response.status === 200) {
          const data = await response.json()
          const sortedData = data.Analysis.sort((a: any, b: any) => new Date(b.AnalyzedAt).getTime() - new Date(a.AnalyzedAt).getTime())
          setAnalysisHistory(sortedData)
        }
      })
  }, [])

  const handleAnalyze = async () => {
    if (!file || selectedRules.length === 0) {
      alert("Please upload a file or select a rule!")
      return
    }

    setLoading(true)

    const formData = new FormData()
    formData.append("file", file)
    formData.append("rules", JSON.stringify(selectedRules))

    try {
      const response = await fetch(apiUrl + "/analysis", {
        method: "POST",
        body: formData,
        headers: {
          "Authorization": `Bearer ${localStorage.getItem("authToken")}`
        }
      })

      if (response.status === 200) {
        const results = await response.json()
        window.location.href = '/analysis?id=' + results.ResultId
      } else {
        const data = await response.json()
        alert(data.message)
      }
    } catch (error) {
      console.error("Analysis failed:", error)
    } finally {
      setLoading(false)
    }
  }

  const handleDeleteCustomRule = async (ruleId: string) => {
    try {
      const response = await fetch(apiUrl + "/rules/" + ruleId, {
        method: "DELETE",
        headers: {
          "Authorization": `Bearer ${localStorage.getItem("authToken")}`
        }
      });

      if (response.ok) {
        alert("Custom rule successfully deleted!");
      } else {
        alert("An error occurred while deleting the rule.");
      }
    } catch (error) {
      console.error("Deleting error:", error);
      alert("Failed to connect to the server");
    }
  };

  const handlePageChange = (pageNumber: number) => {
    setCurrentPage(pageNumber);
  };

  const paginatedAnalysisHistory = analysisHistory.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  return (
    <ClientLayout>
      <div className="relative max-w-2xl mx-auto">
        <div className="absolute inset-0 bg-gradient-to-r from-orange-400 to-orange-500 shadow-xl transform -skew-y-6 sm:skew-y-0 sm:-rotate-3 sm:rounded-3xl opacity-90"></div>
        <div className="relative px-4 py-10 bg-white shadow-xl sm:rounded-3xl sm:p-16 overflow-hidden">
          {/* Flu Logo Arka Plan */}
          <div
            className="absolute inset-0 pointer-events-none z-0"
            style={{
              backgroundImage: 'url("/logo2.png")',
              backgroundPosition: "center",
              backgroundRepeat: "no-repeat",
              backgroundSize: "100%",
              opacity: 0.2,
              filter: "blur(1px)"
            }}
          />

          {/* Ana İçerik */}
          <div className="relative z-10 max-w-lg mx-auto">
            <h1 className="text-3xl font-bold text-black mb-8 text-center">DPUSEC PCAP Analyzer</h1>

            <div className="space-y-8">
              <FileUpload
              className="border-2 border-dashed border-orange-300 rounded-lg p-6 text-center"

                file={file}
                setFile={setFile}
              />
              <RuleSelection 
                selectedRules={selectedRules} 
                setSelectedRules={setSelectedRules}
              />
              <CustomRuleUpload />

              <div className="pt-6">
                <button
                  onClick={handleAnalyze}
                  className="bg-orange-500 hover:bg-orange-600 text-white font-bold py-3 px-6 rounded-xl w-full transition-all duration-300 shadow-lg hover:shadow-xl"
                  disabled={loading}
                >
                  Analyze
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <main className="container mx-auto p-4">
        <h2 className="text-2xl font-bold mb-4 text-black">Historical Analysis</h2>

        <div className="overflow-x-auto">
          <table className="min-w-full bg-white/90 backdrop-blur-sm border border-orange-100 rounded-lg overflow-hidden">
            <thead className="bg-orange-50">
              <tr>
                <th className="px-6 py-3 text-left text-sm font-semibold text-black">Date</th>
                <th className="px-6 py-3 text-left text-sm font-semibold text-black">Pcap File Name</th>
                <th className="px-6 py-3 text-left text-sm font-semibold text-black">Process</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {paginatedAnalysisHistory.map((item) => (
                <tr key={item.ID} className="hover:bg-black-50">
                  <td className="px-6 py-4 whitespace-nowrap text-black">
                    {new Date(item.AnalyzedAt).toLocaleDateString('tr-TR', {
                      year: 'numeric',
                      month: '2-digit',
                      day: '2-digit',
                    })}, 
                    {new Date(item.AnalyzedAt).toLocaleTimeString('tr-TR', {
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit'
                    })}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-black">{item.FileName}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-black">
                    <Link href={`/analysis?id=${item.ID}`}>View Results</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="flex justify-center mt-4">
          {Array.from({ length: Math.ceil(analysisHistory.length / itemsPerPage) }, (_, index) => (
            <button
              key={index}
              onClick={() => handlePageChange(index + 1)}
              className={`mx-1 px-3 py-1 rounded ${currentPage === index + 1 ? 'bg-orange-500 text-white' : 'bg-white text-black'}`}
            >
              {index + 1}
            </button>
          ))}
        </div>
      </main>
      {loading && <LoadingScreen />}
    </ClientLayout>
  )
}

