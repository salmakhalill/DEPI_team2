import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import LandingPage  from './pages/LandingPage';
import NewScanPage  from './pages/NewScanPage';
import LiveScanPage from './pages/LiveScanPage';
import ReportPage   from './pages/ReportPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/"                       element={<LandingPage />} />
        <Route path="/scan/new"               element={<NewScanPage />} />
        <Route path="/scan/:scanId/live"      element={<LiveScanPage />} />
        <Route path="/scan/:scanId/report"    element={<ReportPage />} />
        <Route path="*"                       element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
