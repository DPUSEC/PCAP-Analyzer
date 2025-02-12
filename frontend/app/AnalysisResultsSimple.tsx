"use client"

import { useState, useMemo, useEffect } from "react"
import type { CombinedAnalysisResult } from "@/types/analysis"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Pagination } from "@/components/ui/pagination"
import { Input } from "@/components/ui/input"
import { Select } from "@/components/ui/select"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts"
import Footer from "@/components/Footer"
import axios from "axios"
import { apiUrl } from "@/constants"
import { useSearchParams } from "next/navigation";

const formatDate = (date: Date) => {
  return new Intl.DateTimeFormat('tr-TR', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }).format(date)
}

export function AnalysisResultsSimple() {
  const [results, setResults] = useState<any[]>([])
  const searchParams = useSearchParams();
  const analysisId  = searchParams.get("id");  const [currentPage, setCurrentPage] = useState(1)

  useEffect(() => {
    const fetchData = async () => {
      if (!analysisId) return;

      try {
        const response = await axios.get(apiUrl + `/analysis/${analysisId}`, {
          headers: {
            'Authorization': 'Bearer '+localStorage.getItem('authToken'), // Replace with actual token
            'Content-Type': 'application/json'
          }
        }); // Ensure this endpoint is correct
        const alerts = response.data.Analysis.Alerts; // Ensure this matches the data structure
        if (alerts === null) {alert("No data found"); window.location.href='/'; return;}
        setResults(alerts); // Alerts dizisini results state'ine ayarlayın
      } catch (error) {
        console.error("Data extraction error:", error);
      }
    };

    fetchData();
  }, [analysisId]);

  const [columnFilters, setColumnFilters] = useState({
    Timestamp: '',
    SrcIp: '',
    DstIp: '',
    TransmissionProtocol: '',
    Signature: '',
    Severity: ''
  })
  const [sortField, setSortField] = useState<keyof CombinedAnalysisResult>("timestamp")
    const [sortDirection, setSortDirection] = useState<"asc" | "desc">("desc")
  const [pageSize, setPageSize] = useState(10)

  const filteredAndSortedResults = useMemo(() => {
    return results.filter(result => {
      const srcIpMatch = result.SrcIp.toLowerCase().includes(columnFilters.SrcIp.toLowerCase())
      const destIpMatch = result.DstIp.toLowerCase().includes(columnFilters.DstIp.toLowerCase())
      const protoMatch = result.TransmissionProtocol.toLowerCase().includes(columnFilters.TransmissionProtocol.toLowerCase())
      const signatureMatch = result.Alert.Signature.toLowerCase().includes(columnFilters.Signature.toLowerCase())
      const timestampMatch = formatDate(new Date(result.Timestamp)).includes(columnFilters.Timestamp)
      const severityMatch = result.Alert.Severity.toString().includes(columnFilters.Severity)


      return (
        (srcIpMatch || destIpMatch || protoMatch || signatureMatch || timestampMatch || severityMatch) &&
        (columnFilters.SrcIp ? srcIpMatch : true) &&
        (columnFilters.DstIp ? destIpMatch : true) &&
        (columnFilters.TransmissionProtocol ? protoMatch : true) &&
        (columnFilters.Timestamp ? timestampMatch : true) &&
        (columnFilters.Severity ? severityMatch : true) &&
        (columnFilters.Signature ? signatureMatch : true)

      )
    }).sort((a, b) => {
      const aValue = sortField === "Severity" ? a.Alert.Severity : a[sortField];
      const bValue = sortField === "Severity" ? b.Alert.Severity : b[sortField];

      if (aValue < bValue) return sortDirection === "asc" ? -1 : 1;
      if (aValue > bValue) return sortDirection === "asc" ? 1 : -1;
      return 0;
    })
  }, [results, sortField, sortDirection, columnFilters])

  const paginatedResults = filteredAndSortedResults.slice((currentPage - 1) * pageSize, currentPage * pageSize)

  const chartData = useMemo(() => {
    const alertCounts: { [key: string]: number } = {}
    filteredAndSortedResults.forEach((result) => {
      if (typeof result.Alert === "object") {
        alertCounts[result.Alert.Signature] = (alertCounts[result.Alert.Signature] || 0) + 1
      }
    })
    return Object.entries(alertCounts).map(([name, value]) => ({ name, value }))
  }, [filteredAndSortedResults])

  const pageSizeOptions = [10, 25, 50, 100]

  return (
    <>
      <div className="space-y-6 text-black">


        <div className="h-64 w-full">
        <h2 className="text-lg font-semibold mb-2 text-center">Signature Chart</h2>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip
                contentStyle={{
                  color: '#000',
                  backgroundColor: '#fff',
                  border: '1px solid #e5e7eb',
                  borderRadius: '6px',
                  padding: '8px'
                }}
              />
              <Legend />
              <Bar dataKey="value" fill="#8884d8" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>
                <Input
                  placeholder="Filter time"
                  value={columnFilters.Timestamp}
                  onChange={(e) => setColumnFilters(prev => ({ ...prev, Timestamp: e.target.value }))}
                  className="max-w-[120px] text-xs h-8"
                />
              </TableHead>
              <TableHead>
                <Input
                  placeholder="Search for source IP"
                  value={columnFilters.SrcIp}
                  onChange={(e) => setColumnFilters(prev => ({ ...prev, SrcIp: e.target.value }))}
                  className="max-w-[160px] text-xs h-8"
                />
              </TableHead>
              <TableHead>
                <Input
                  placeholder="Destination IP search"
                  value={columnFilters.DstIp}
                  onChange={(e) => setColumnFilters(prev => ({ ...prev, DstIp: e.target.value }))}
                  className="max-w-[160px] text-xs h-8"
                />
              </TableHead>
              <TableHead>
                <Input
                  placeholder="Protocol search"
                  value={columnFilters.TransmissionProtocol}
                  onChange={(e) => setColumnFilters(prev => ({ ...prev, TransmissionProtocol: e.target.value }))}
                  className="max-w-[130px] text-xs h-8"
                />
              </TableHead>
              <TableHead>
                <Input
                  placeholder="Alert search"
                  value={columnFilters.Signature}
                  onChange={(e) => setColumnFilters(prev => ({ ...prev, Signature: e.target.value }))}
                  className="max-w-[130px] text-xs h-8"
                />
              </TableHead>
              <TableHead>
                <TableHead>
                  <Input
                    placeholder="Severity search"
                    value={columnFilters.Severity}
                    onChange={(e) => setColumnFilters(prev => ({ ...prev, Severity: e.target.value }))}
                    className="max-w-[130px] text-xs h-8"
                  />
                </TableHead>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {paginatedResults.map((result, index) => (
              <TableRow key={index}>
                <TableCell className="text-black">{formatDate(new Date(result.Timestamp))}</TableCell>
                <TableCell className="text-black">{result.SrcIp}:{result.SrcPort}</TableCell>
                <TableCell className="text-black">{result.DstIp}:{result.DstPort}</TableCell>
                <TableCell className="text-black">{result.TransmissionProtocol}</TableCell>
                <TableCell className="text-black">{result.Alert.Signature}</TableCell>
                <TableCell className="text-black">
                  <span
                    className={`px-2 py-1 rounded-full text-xs ${getPriorityColor(result.Alert.Severity)}`}
                  >
                    {result.Alert.Severity}
                  </span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>



        <div className="flex items-center justify-center gap-2 mt-4">
          <button
            onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
            disabled={currentPage === 1}
            className="px-3 py-1 rounded bg-gray-200 hover:bg-gray-300 disabled:opacity-50"
          >
            ←
          </button>

          <div className="flex items-center gap-1">
            <span className="px-2 py-1 bg-orange-500 text-white rounded">
              {currentPage}
            </span>
            <span>/ {Math.ceil(filteredAndSortedResults.length / pageSize)}</span>
          </div>

          <button
            onClick={() => setCurrentPage(Math.min(Math.ceil(filteredAndSortedResults.length / pageSize), currentPage + 1))}
            disabled={currentPage === Math.ceil(filteredAndSortedResults.length / pageSize)}
            className="px-3 py-1 rounded bg-gray-200 hover:bg-gray-300 disabled:opacity-50"
          >
            →
          </button>
        </div>

        <TableHead>
          <TableHead>
            <Select
              value={pageSize.toString()}
              onChange={(e) => setPageSize(Number(e.target.value))}
              className="h-8 text-xs w-[80px]"
            >
              {pageSizeOptions.map(option => (
                <option key={option} value={option}>{option}/sayfa</option>
              ))}
            </Select>
          </TableHead>
        </TableHead>
      </div>
    </>
  )
}

function getPriorityColor(priority: number): string {
  switch (priority) {
    case 1:
      return "bg-red-100 text-red-800"
    case 2:
      return "bg-orange-100 text-orange-800"
    case 3:
      return "bg-yellow-100 text-yellow-800"
    default:
      return "bg-green-100 text-green-800"
  }
}

