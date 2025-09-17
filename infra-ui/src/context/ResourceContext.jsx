// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { createContext, useState, useContext, useRef } from "react";
import axios from "axios";

// Create context
const ResourceContext = createContext();

// Provider component
export const ResourceProvider = ({ children }) => {
  const [resources, setResources] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [hasScanned, setHasScanned] = useState(false);

  // Analysis state
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [analysisError, setAnalysisError] = useState(null);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [analysisStartTime, setAnalysisStartTime] = useState(null);

  // Dependency analysis state
  const [isAnalyzingDependencies, setIsAnalyzingDependencies] = useState(false);
  const [dependencyResult, setDependencyResult] = useState(null);
  const [dependencyError, setDependencyError] = useState(null);
  const [dependencyProgress, setDependencyProgress] = useState(0);
  const [dependencyStartTime, setDependencyStartTime] = useState(null);

  // Refs to track ongoing requests
  const analysisControllerRef = useRef(null);
  const dependencyControllerRef = useRef(null);

  const scanResources = async (credentials) => {
    setLoading(true);
    setError(null);

    try {
      // Replace with your actual API endpoint
      console.log("Sending credentials to API:", credentials);
      const response = await axios.post(
        `${import.meta.env.VITE_API_BASE_URL}/api/infra-doc/generate`,
        credentials
      );

      console.log("API Response:", response.data);

      setResources(response.data);
      setHasScanned(true);
      setLoading(false);

      // Reset analysis state when new scan is done
      resetAnalysis();
    } catch (err) {
      console.error("Error scanning resources:", err);
      setError(
        "Failed to scan resources. Please check your credentials and try again."
      );
      setLoading(false);
    }
  };

  const startAnalysis = async (analysisConfig) => {
    // Prevent duplicate analysis if already running
    if (isAnalyzing) {
      console.log("Analysis already in progress, skipping duplicate request");
      return { success: false, message: "Analysis already in progress" };
    }

    if (!resources) {
      setAnalysisError(
        "No infrastructure data available. Please run the infrastructure scan first."
      );
      return { success: false, message: "No infrastructure data available" };
    }

    // Create abort controller for this analysis
    analysisControllerRef.current = new AbortController();

    setIsAnalyzing(true);
    setAnalysisError(null);
    setAnalysisResult(null);
    setAnalysisProgress(5);
    setAnalysisStartTime(Date.now());

    try {
      // Create a blob from the resources data
      const jsonBlob = new Blob([JSON.stringify(resources, null, 2)], {
        type: "application/json",
      });

      // Create FormData
      const formData = new FormData();
      formData.append("file", jsonBlob, "infrastructure_data.json");
      formData.append("analysis_type", analysisConfig.analysisType);
      formData.append("bedrock_region", analysisConfig.bedrockRegion || "us-east-1");

      if (analysisConfig.customPrompt?.trim()) {
        formData.append("custom_prompt", analysisConfig.customPrompt.trim());
      }

      // Make API call with abort signal
      const response = await fetch(
       `${import.meta.env.VITE_API_BASE_URL}/api/infra-analysis/generate-report-from-file`,
        {
          method: "POST",
          body: formData,
          signal: analysisControllerRef.current.signal,
        }
      );
      console.log("response: ", response);
      const result = await response.json();
      console.log("result: ", result);
      if (result && result.report_markdown) {
        setAnalysisResult(result);
        setAnalysisProgress(100);
        return { success: true, result };
      } else {
        throw new Error(result.error || "Analysis failed");
      }
    } catch (err) {
      if (err.name === "AbortError") {
        console.log("Analysis was cancelled");
        return { success: false, message: "Analysis cancelled" };
      }

      console.error("Analysis error:", err);
      setAnalysisError(`Analysis failed: ${err.message}`);
      return { success: false, message: err.message };
    } finally {
      setIsAnalyzing(false);
      analysisControllerRef.current = null;
    }
  };

  const cancelAnalysis = () => {
    if (analysisControllerRef.current) {
      analysisControllerRef.current.abort();
      setIsAnalyzing(false);
      setAnalysisProgress(0);
      analysisControllerRef.current = null;
    }
  };

  const resetAnalysis = () => {
    cancelAnalysis();
    setAnalysisResult(null);
    setAnalysisError(null);
    setAnalysisProgress(0);
    setAnalysisStartTime(null);
  };

  const resetScan = () => {
    setResources(null);
    setHasScanned(false);
    setError(null);
    resetAnalysis();
  };

  const updateAnalysisProgress = (progress) => {
    setAnalysisProgress(progress);
  };

  // Dependency analysis functions
  const startDependencyAnalysis = async (dependencyConfig = {}) => {
    // Prevent duplicate analysis if already running
    if (isAnalyzingDependencies) {
      console.log(
        "Dependency analysis already in progress, skipping duplicate request"
      );
      return {
        success: false,
        message: "Dependency analysis already in progress",
      };
    }

    if (!resources) {
      setDependencyError(
        "No infrastructure data available. Please run the infrastructure scan first."
      );
      return { success: false, message: "No infrastructure data available" };
    }

    // Create abort controller for this analysis
    dependencyControllerRef.current = new AbortController();

    setIsAnalyzingDependencies(true);
    setDependencyError(null);
    setDependencyResult(null);
    setDependencyProgress(5);
    setDependencyStartTime(Date.now());

    try {
      // Create a blob from the resources data to send as file
      const resourcesBlob = new Blob([JSON.stringify(resources, null, 2)], {
        type: "application/json",
      });

      // Create FormData to send the data as a file
      const formData = new FormData();
      formData.append("file", resourcesBlob, "infrastructure-data.json");
      formData.append(
        "custom_prompt",
        dependencyConfig.customPrompt || "Focus on resource dependencies and security relationships"
      );
      formData.append("bedrock_region", dependencyConfig.bedrockRegion || "us-east-1");

      // Call the resource mapping API
      const response = await fetch(
     `${import.meta.env.VITE_API_BASE_URL}/api/resource-mapping/generate-from-infra-data`,
        {
          method: "POST",
          body: formData,
          signal: dependencyControllerRef.current.signal,
        }
      );
      // Check if response is ok
      if (!response) {
        const errorText = await response.text();
        console.error("API Response Error:", errorText);
        throw new Error(
          `API request failed: ${response.status} ${response.statusText}`
        );
      }

      // Check content type
      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        const responseText = await response.text();
        console.error("Non-JSON Response:", responseText);
        throw new Error(
          "API returned non-JSON response. Check server logs for errors."
        );
      }

      const result = await response.json();
      console.log("response: ", result);
      if (result.error) {
        throw new Error(
          result.message || "Failed to generate resource mapping"
        );
      }

      setDependencyResult(result);
      setDependencyProgress(100);
      return { success: true, result };
    } catch (err) {
      if (err.name === "AbortError") {
        console.log("Dependency analysis was cancelled");
        return { success: false, message: "Dependency analysis cancelled" };
      }

      console.error("Dependency analysis error:", err);
      setDependencyError(`Failed to analyze dependencies: ${err.message}`);
      return { success: false, message: err.message };
    } finally {
      setIsAnalyzingDependencies(false);
      dependencyControllerRef.current = null;
    }
  };

  const cancelDependencyAnalysis = () => {
    if (dependencyControllerRef.current) {
      dependencyControllerRef.current.abort();
      setIsAnalyzingDependencies(false);
      setDependencyProgress(0);
      dependencyControllerRef.current = null;
    }
  };

  const resetDependencyAnalysis = () => {
    cancelDependencyAnalysis();
    setDependencyResult(null);
    setDependencyError(null);
    setDependencyProgress(0);
    setDependencyStartTime(null);
  };

  const updateDependencyProgress = (progress) => {
    setDependencyProgress(progress);
  };

  return (
    <ResourceContext.Provider
      value={{
        // Scan state
        resources,
        loading,
        error,
        hasScanned,
        scanResources,
        resetScan,

        // Analysis state
        isAnalyzing,
        analysisResult,
        analysisError,
        analysisProgress,
        analysisStartTime,
        startAnalysis,
        cancelAnalysis,
        resetAnalysis,
        updateAnalysisProgress,

        // Dependency analysis state
        isAnalyzingDependencies,
        dependencyResult,
        dependencyError,
        dependencyProgress,
        dependencyStartTime,
        startDependencyAnalysis,
        cancelDependencyAnalysis,
        resetDependencyAnalysis,
        updateDependencyProgress,
      }}
    >
      {children}
    </ResourceContext.Provider>
  );
};

// Custom hook to use the resource context
export const useResources = () => {
  const context = useContext(ResourceContext);
  if (!context) {
    throw new Error("useResources must be used within a ResourceProvider");
  }
  return context;
};
