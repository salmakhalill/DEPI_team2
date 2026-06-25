import axios from 'axios';
import type { StartScanRequest, StartScanResponse } from '../types/scan';

const BASE_URL = 'http://localhost:8000';

const api = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
});

export const startScan = (data: StartScanRequest) =>
  api.post<StartScanResponse>('/api/scan/start/', data);

export const getReportUrl = (scanId: string) =>
  `${BASE_URL}/api/scan/${scanId}/report/`;

export const WS_URL = (scanId: string) =>
  `ws://localhost:8000/ws/scan/${scanId}/`;

export default api;
