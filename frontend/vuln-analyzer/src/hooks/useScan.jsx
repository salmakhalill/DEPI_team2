/**
 * useScan.js
 * Now supports multiple vulnerabilities + selected vulnerability state
 */

import { useState, useCallback } from "react";
import { simulateScan } from "../data/mockData";

export function useScan() {
  const [url, setUrl] = useState("");
  const [phase, setPhase] = useState("idle");
  const [result, setResult] = useState(null);           // { vulnerabilities: [...] }
  const [selectedVulnIndex, setSelectedVulnIndex] = useState(0);
  const [activeStations, setActiveStations] = useState(0);
  const [error, setError] = useState("");

  const handleScan = useCallback(async () => {
    if (!url.trim()) {
      setError("Please enter a target URL.");
      return;
    }

    setError("");
    setResult(null);
    setActiveStations(0);
    setSelectedVulnIndex(0);
    setPhase("scanning");

    try {
      await new Promise((r) => setTimeout(r, 900));
      setPhase("analyzing");

      const res = await simulateScan(url.trim());

      setPhase("finalizing");
      await new Promise((r) => setTimeout(r, 600));

      setResult(res);
      setPhase("done");

      // Staggered reveal for the first vulnerability
      const firstVulnSteps = res.vulnerabilities[0].data.steps.length;
      for (let i = 1; i <= firstVulnSteps; i++) {
        await new Promise((r) => setTimeout(r, 500));
        setActiveStations(i);
      }
    } catch (err) {
      setPhase("error");
      setError("Scan failed. Check target connectivity.");
    }
  }, [url]);

  // Change selected vulnerability and reset station animation
  const selectVulnerability = (index) => {
    setSelectedVulnIndex(index);
    setActiveStations(0);

    const selectedSteps = result.vulnerabilities[index].data.steps.length;
    // Re-animate stations
    setTimeout(async () => {
      for (let i = 1; i <= selectedSteps; i++) {
        await new Promise((r) => setTimeout(r, 400));
        setActiveStations(i);
      }
    }, 100);
  };

  const isScanning = phase !== "idle" && phase !== "done" && phase !== "error";

  const currentVulnerability = result?.vulnerabilities?.[selectedVulnIndex];

  return {
    url,
    setUrl,
    phase,
    result,
    activeStations,
    error,
    isScanning,
    handleScan,
    selectedVulnIndex,
    selectVulnerability,
    currentVulnerability,
  };
}