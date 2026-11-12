export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export type OriginType = 'uploaded' | 'sample' | 'simulated';

export interface SecurityEvent {
  id: number;
  event_hash: string;
  timestamp: string;
  ingestion_timestamp: string;
  dataset_id: string;
  origin_type: OriginType;
  source: string;
  hostname: string;
  username?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  event_type: string;
  event_id?: string | null;
  severity: Severity;
  raw_message: string;
  normalized_data: Record<string, unknown>;
}

export interface DetectionRule {
  rule_id: string;
  name: string;
  description: string;
  detection_logic: string;
  severity: Severity;
  mitre_tactic: string;
  mitre_technique: string;
  threshold_count: number;
  time_window_seconds: number;
  enabled: number;
  recommended_steps: string;
  updated_at: string;
}

export interface SecurityAlert {
  alert_id: string;
  title: string;
  description: string;
  severity: Severity;
  rule_id: string;
  rule_name: string;
  source_ip?: string | null;
  username?: string | null;
  hostname: string;
  first_observed: string;
  last_observed: string;
  event_count: number;
  mitre_technique: string;
  recommended_actions: string;
  status: 'New' | 'Acknowledged' | 'Investigating' | 'Escalated' | 'Resolved' | 'False Positive';
  assigned_analyst: string;
  origin_type: OriginType;
  investigation_notes: Array<{ author: string; timestamp: string; note: string }>;
  evidence: Array<{ id: number; event_id: number; evidence_summary: string }>;
  created_at: string;
}

export interface Incident {
  incident_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: 'New' | 'Triage' | 'Investigation' | 'Containment' | 'Resolved' | 'Closed';
  assigned_analyst: string;
  related_alerts: string[];
  iocs: string[];
  resolution_summary?: string | null;
  created_at: string;
  updated_at: string;
  closed_at?: string | null;
  timeline: Array<{ id: number; author: string; note_type: string; content: string; created_at: string }>;
}
