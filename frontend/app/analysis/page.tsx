"use client"

import { useEffect, useState } from 'react'
import AnalysisResults from '@/app/AnalysisResults'
import { apiUrl } from '@/constants'

// JSON dönüşüm fonksiyonu
const convertToJSON = (data: any) => {
  return JSON.stringify(data.results, null, 2)
}

export default function AnalysisPage() {
  const [results, setResults] = useState(null)
  const [isLoading, setIsLoading] = useState(true)

  const handleDownload = () => {
    if (!results) return

    const jsonContent = JSON.stringify(results.Alerts)
    const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' })
    const link = document.createElement('a')
    const url = URL.createObjectURL(blob)

    link.setAttribute('href', url)
    link.setAttribute('download', `analysis-results-${results.ID}.json`)
    link.style.visibility = 'hidden'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search)
    const analysisId = searchParams.get('id')

    setIsLoading(true)
    fetch(apiUrl + `/analysis/${analysisId}`, {
      headers: {
        "Authorization": `Bearer ${localStorage.getItem("authToken")}`
      }
    })
      .then(async (response) => {
        if (response.status === 200) {
          const data = await response.json()
          setResults(data.Analysis)
        } else {
          const data = await response.json()
          alert(data.message)
        }
      })
      .catch(() => {
        alert("Connection error occurred.")
      })
      .finally(() => {
        setIsLoading(false)
      })
  }, [])

  return (
    <div className="container mx-auto p-8">
      {isLoading ? (
        <div className="flex justify-center items-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-green-500"></div>
          <span className="ml-3 text-lg">Analysis results are loading...</span>
        </div>
      ) : results ? (
        <div>
          <button
            onClick={handleDownload}
            className="mb-4 bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded"
          >
            Download Results as JSON

          </button>
          <AnalysisResults data={results} />
        </div>
      ) : (
        <div className="text-center text-orange-600">
          Analysis results could not be loaded. Please try again.

        </div>
      )}
    </div>
  )
}