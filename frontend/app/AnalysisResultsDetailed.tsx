"use client"

import { useState, useMemo, useEffect } from "react"
import type { CombinedAnalysisResult } from "@/types/analysis"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Pagination } from "@/components/ui/pagination"
import { Input } from "@/components/ui/input"
import { Select } from "@/components/ui/select"
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend, BarChart,Line, LineChart, Bar, CartesianGrid, XAxis, YAxis } from "recharts"
import axios from "axios"
import { apiUrl } from "@/constants"
import { useSearchParams } from "next/navigation";
const PAGE_SIZE = 5

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

type SortableFields = "Timestamp" | "SrcIp" | "DstIp" | "TransmissionProtocol"

export function AnalysisResultsDetailed() {
  const [results, setResults] = useState<CombinedAnalysisResult[]>([])
  const [exportedFiles, setExportedFiles] = useState<string[] | null>(null)
  const searchParams = useSearchParams();
  const analysisId = searchParams.get("id"); const [currentPage, setCurrentPage] = useState(1)
  const fileExport = searchParams.get("id"); const [currentPagee, setCurrentPagee] = useState(1)

  const [columnFilters, setColumnFilters] = useState({
    Timestamp: '',
    SrcIp: '',
    DstIp: '',
    TransmissionProtocol: '',
    Signature: '',
    Severity: ''
  })
  const [pageSize, setPageSize] = useState(5)
  const [sortField, setSortField] = useState<SortableFields>("Timestamp")
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("desc")

  useEffect(() => {
    const fetchData = async () => {
      if (!analysisId) return;

      try {
        const response = await axios.get(apiUrl + `/analysis/${analysisId}`, {
          headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('authToken'), // Replace with actual token
            'Content-Type': 'application/json'
          }
        })
        const Alerts = response.data.Analysis.Alerts; // Ensure this matches the data structure
        setExportedFiles(response.data.Analysis.ExportedFiles)
        if (Alerts === null) {/*alert("No data found"); window.location.href='/'; */return; }
        setResults(Alerts); // Alerts dizisini results state'ine ayarlayın
      } catch (error) {
        console.error("Data extrAction error:", error);
      }
    };

    fetchData();
  }, [analysisId]);

  const downloadFile = (url: string, filename: string) => {
    fetch(apiUrl.replace("/api/v1", "") + url, {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + localStorage.getItem('authToken')
      }
    })
      .then(response => response.blob())
      .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
      });
  }

  const filteredAndSortedResults = useMemo(() => {
    return results.filter(result => {
      const srcIpMatch = result.SrcIp.toLowerCase().includes(columnFilters.SrcIp.toLowerCase())
      const destIpMatch = result.DstIp.toLowerCase().includes(columnFilters.DstIp.toLowerCase())
      const protoMatch = result.TransmissionProtocol.toLowerCase().includes(columnFilters.TransmissionProtocol.toLowerCase())
      const signatureMatch = result.Alert.Signature.toLowerCase().includes(columnFilters.Signature.toLowerCase())
      const timestampMatch = formatDate(new Date(result.Timestamp)).includes(columnFilters.Timestamp)
      const severityMatch = result.Alert.Severity.toString().includes(columnFilters.Severity)

      return (
        (columnFilters.SrcIp ? srcIpMatch : true) &&
        (columnFilters.DstIp ? destIpMatch : true) &&
        (columnFilters.TransmissionProtocol ? protoMatch : true) &&
        (columnFilters.Timestamp ? timestampMatch : true) &&
        (columnFilters.Severity ? severityMatch : true) &&
        (columnFilters.Signature ? signatureMatch : true)
      )
    }).sort((a, b) => {
      if (a[sortField] < b[sortField]) return sortDirection === "asc" ? -1 : 1
      if (a[sortField] > b[sortField]) return sortDirection === "asc" ? 1 : -1
      return 0
    })
  }, [results, sortField, sortDirection, columnFilters])

  const paginatedResults = filteredAndSortedResults.slice((currentPage - 1) * pageSize, currentPage * pageSize)

  const chartData = useMemo(() => {
    const protocolCounts: { [key: string]: number } = {}
    filteredAndSortedResults.forEach((result) => {
      protocolCounts[result.TransmissionProtocol] = (protocolCounts[result.TransmissionProtocol] || 0) + 1
    })
    return Object.entries(protocolCounts).map(([name, value]) => ({ name, value }))
  }, [filteredAndSortedResults])

  const chartData2 = useMemo(() => {
    const protocolCounts: { [key: string]: number } = {}
    filteredAndSortedResults.forEach((result) => {
      protocolCounts[result.Alert.Action] = (protocolCounts[result.Alert.Action] || 0) + 1
    })
    return Object.entries(protocolCounts).map(([name, value]) => ({ name, value }))
  }, [filteredAndSortedResults])

  const chartData3 = useMemo(() => {
    const protocolCounts: { [key: string]: number } = {}
    filteredAndSortedResults.forEach((result) => {
      protocolCounts[result.Alert.Severity] = (protocolCounts[result.Alert.Severity] || 0) + 1
    })
    return Object.entries(protocolCounts).map(([name, value]) => ({ name, value }))
  }, [filteredAndSortedResults])


  const chartData4 = useMemo(() => {
    const protocolCounts: { [key: string]: number } = {}
    filteredAndSortedResults.forEach((result) => {
      protocolCounts[result.DstPort] = (protocolCounts[result.DstPort] || 0) + 1
    })
    return Object.entries(protocolCounts).map(([name, value]) => ({ name, value }))
  }, [filteredAndSortedResults])

  const chartData5 = useMemo(() => {
    const timestampCounts: { [key: string]: number } = {}
    filteredAndSortedResults.forEach((result) => {
      const formattedTimestamp = formatDate(new Date(result.Timestamp))
      timestampCounts[formattedTimestamp] = (timestampCounts[formattedTimestamp] || 0) + 1
    })
    return Object.entries(timestampCounts).map(([name, value]) => ({ name, value }))
  }, [filteredAndSortedResults])

  const COLORS = ["#FF6B35", "#FF9F1C", "#FFD700", "#FFAA33"]

  return (
    <div className="space-y-6 text-black">
      <div className="flex justify-between items-center">
        <Input
          placeholder="Source IP filter"
          value={columnFilters.SrcIp}
          onChange={(e) => setColumnFilters(prev => ({ ...prev, SrcIp: e.target.value }))}
          className="max-w-sm"
        />
        <Input
          placeholder="Destination IP filter"
          value={columnFilters.DstIp}
          onChange={(e) => setColumnFilters(prev => ({ ...prev, DstIp: e.target.value }))}
          className="max-w-sm"
        />
        <Input
          placeholder="Protocol filter"
          value={columnFilters.TransmissionProtocol}
          onChange={(e) => setColumnFilters(prev => ({ ...prev, TransmissionProtocol: e.target.value }))}
          className="max-w-sm"
        />
        <Input
          placeholder="Timestamp filter"
          value={columnFilters.Timestamp}
          onChange={(e) => setColumnFilters(prev => ({ ...prev, Timestamp: e.target.value }))}
          className="max-w-sm"
        />
        <Input
          placeholder="Severity filter"
          value={columnFilters.Severity}
          onChange={(e) => setColumnFilters(prev => ({ ...prev, Severity: e.target.value }))}
          className="max-w-sm"
        />
        <Input
          placeholder="Signature filter"
          value={columnFilters.Signature}
          onChange={(e) => setColumnFilters(prev => ({ ...prev, Signature: e.target.value }))}
          className="max-w-sm"
        />
        <button
          onClick={() => setSortDirection(sortDirection === "asc" ? "desc" : "asc")}
          className="p-2 bg-gray-200 rounded"
        >
          {sortDirection === "asc" ? "↑" : "↓"}
        </button>
      </div>

      <div className="flex justify-center gap-4 w-full overflow-x-auto">
        <div className="w-1/4 text-center">
          <h2 className="text-lg font-semibold mb-2">Protocol</h2>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={chartData} cx="50%" cy="50%" labelLine={false} outerRadius={80} fill="#8884d8" dataKey="value">
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ color: '#000' }} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="w-1/4 text-center">
          <h2 className="text-lg font-semibold mb-2">Status</h2>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={chartData2} cx="50%" cy="50%" labelLine={false} outerRadius={80} fill="#8884d8" dataKey="value">
                {chartData2.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ color: '#000' }} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="w-1/4 text-center">
          <h2 className="text-lg font-semibold mb-2">Severity</h2>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={chartData3} cx="50%" cy="50%" labelLine={false} outerRadius={80} fill="#8884d8" dataKey="value">
                {chartData3.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ color: '#000' }} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="w-1/4 text-center">
          <h2 className="text-lg font-semibold mb-2">Destination Port</h2>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={chartData4} cx="50%" cy="50%" labelLine={false} outerRadius={80} fill="#8884d8" dataKey="value">
                {chartData4.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ color: '#000' }} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
      
      <div className="w-full text-center">
      <h2 className="text-lg font-semibold mb-2">Timestamp</h2>
      <ResponsiveContainer width="100%" height={250}>
        <LineChart data={chartData5}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="name" />
          <YAxis />
          <Tooltip contentStyle={{ color: '#000' }} />
          <Legend />
          <Line type="monotone" dataKey="value" stroke="#8884d8" />
        </LineChart>
      </ResponsiveContainer>
    </div>


      

      <div className="space-y-4">
        {paginatedResults.map((result, index) => (
          <Card className="bg-white/90 backdrop-blur-sm hover:shadow-lg transition-shadow" key={index}>
            <CardHeader className="bg-orange-50 rounded-t-lg">
              <CardTitle className="text-orange-800 flex justify-between items-center">
                <span>Signature Id: {result.Alert.SignatureId}</span>
                <span className={`px-3 py-1 rounded-full text-sm ${typeof result.Alert === "object" && result.Alert.Action === "allowed"
                  ? "bg-green-100 text-green-800"
                  : "bg-red-100 text-red-800"
                  }`}>
                  {typeof result.Alert === "object" ? result.Alert.Action : "N/A"}
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <p>
                    <span className="font-medium">Time:</span> {(result.Timestamp)}
                  </p>
                  <p>
                    <span className="font-medium">Source:</span> {result.SrcIp}:{result.SrcPort}
                  </p>
                  <p>
                    <span className="font-medium">Destination:</span> {result.DstIp}:{result.DstPort}
                  </p>
                  <p>
                    <span className="font-medium">Protocol:</span> {result.TransmissionProtocol}
                  </p>
                </div>
                <div className="space-y-2">
                  <p>
                    <span className="font-medium">Alert Details:</span>
                  </p>
                  {typeof result.Alert === "object" && (
                    <>
                      <p>
                        <span className="font-medium">Signature:</span> {result.Alert.Signature}
                      </p>
                      <p>
                        <span className="font-medium">Severity:</span> {result.Alert.Severity}
                      </p>
                      {result.Alert.Category && (
                        <p>
                          <span className="font-medium">Category:</span> {result.Alert.Category}
                        </p>
                      )}
                    </>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex items-center justify-center gap-2">
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
      <Table>
        <TableHeader>
          <TableRow>
        <TableHead>
          <Input
            placeholder="File Name"
            value={columnFilters.TransmissionProtocol}
            onChange={(e) => setColumnFilters(prev => ({ ...prev, TransmissionProtocol: e.target.value }))}
            className="max-w-[100px] text-xs h-8"
          />
        </TableHead>
        <TableHead></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {exportedFiles?.slice((currentPagee - 1) * pageSize, currentPagee * pageSize).map((result, index) => (
        <TableRow key={index}>
          <TableCell className="text-black"> {result.FileName} </TableCell>
          <TableCell className="text-black"><button onClick={() => downloadFile(result.DownloadLink, result.FileName)} >Download File</button></TableCell>
        </TableRow>
          ))}
        </TableBody>
      </Table>

      <div className="flex items-center justify-center gap-2">
        <button
          onClick={() => setCurrentPagee(Math.max(1, currentPagee - 1))}
          disabled={currentPagee === 1}
          className="px-3 py-1 rounded bg-gray-200 hover:bg-gray-300 disabled:opacity-50"
        >
          ←
        </button>

        <div className="flex items-center gap-1">
          <span className="px-2 py-1 bg-orange-500 text-white rounded">
        {currentPagee}
          </span>
          <span>/ {Math.ceil((exportedFiles?.length || 0) / pageSize)}</span>
        </div>

        <button
          onClick={() => setCurrentPagee(Math.min(Math.ceil((exportedFiles?.length || 0) / pageSize), currentPagee + 1))}
          disabled={currentPagee === Math.ceil((exportedFiles?.length || 0) / pageSize)}
          className="px-3 py-1 rounded bg-gray-200 hover:bg-gray-300 disabled:opacity-50"
        >
          →
        </button>
      </div>
    </div>
  )
}

