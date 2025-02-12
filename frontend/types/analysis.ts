export interface AnalysisResult {
  id: string
  timestamp: Date
  src_ip: string
  src_port: number
  dest_ip: string
  dest_port: number
  proto: string
  alert: Alert | string
}

interface Alert {
  action: string
  signature: string
  severity: number
  category?: string
}

export interface CombinedAnalysisResult extends AnalysisResult {
  flow_id: number
  event_type: string
  Severity: number
} 