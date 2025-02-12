import type { ChangeEvent } from "react"
import { Upload } from "lucide-react"
import { cn } from "../lib/utils"

interface FileUploadProps {
  file: File | null
  setFile: (file: File | null) => void
  className?: string
}

export function FileUpload({ file, setFile, className }: FileUploadProps) {
  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      setFile(event.target.files[0])
    }
  }

  return (
    <div className={cn("space-y-4", className)}>
      <div className="flex items-center space-x-2">
        <Upload className="w-6 h-6 text-orange-500" />
        <span className="font-bold text-black">Select PCAP file</span>
      </div>
      <input
        type="file"
        accept=".pcap, .pcapng"
        onChange={handleFileChange}
        className="w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-orange-50 file:text-orange-700 hover:file:bg-orange-100"
      />
      {file && (
        <p className="text-sm text-black-500">
          Select File: <span className="font-medium">{file.name}</span>
        </p>
      )}
    </div>
  )
}

