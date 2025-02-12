"use client"
import { useState } from 'react'
import { Pie, Bar } from 'react-chartjs-2'
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js'
import { AnalysisResultsDetailed } from "@/app/AnalysisResultsDetailed"
import { AnalysisResultsSimple } from "@/app/AnalysisResultsSimple"
import Footer from '@/components/Footer'

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement)

// Örnek veri seti

export default function AnalysisResults({ data }: { data: any }) {
  return (
    <div className="space-y-8">
      <h1 className="text-2xl font-bold text-black">Analysis Result</h1>
      <AnalysisResultsSimple />
      <AnalysisResultsDetailed />
      <Footer />
    </div>
  )
}

const StatCard = ({ title, value }: { title: string; value: string | number }) => (
  <div className="bg-black-50 p-4 rounded-lg">
    <h4 className="text-sm text-black-500">{title}</h4>
    <p className="text-xl font-bold mt-1">{value}</p>
  </div>
)

