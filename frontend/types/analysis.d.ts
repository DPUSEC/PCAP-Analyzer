export interface CombinedAnalysisResult {
  timestamp: Date
  flow_id: number
  event_type: string
  src_ip: string
  src_port: number
  dest_ip: string
  dest_port: number
  proto: string
  alert: {
    action: string
    signature: string
    category?: string
    severity: number
  }
} 