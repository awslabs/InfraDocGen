// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { useState, useEffect } from "react";
import {
  Container,
  Header,
  SpaceBetween,
  Form,
  FormField,
  Textarea,
  Select,
  Button,
  Alert,
  ProgressBar,
  Box,
  StatusIndicator,
  ColumnLayout,
  Badge,
  Spinner,
  Tabs,
} from "@cloudscape-design/components";
import ReactMarkdown from "react-markdown";
import { useResources } from "../context/ResourceContext";
import "./InfrastructureAnalysis.css";

const InfrastructureAnalysis = () => {
  const {
    resources,
    hasScanned,
    isAnalyzing,
    analysisResult,
    analysisError,
    analysisProgress,
    analysisStartTime,
    startAnalysis,
    cancelAnalysis,
    resetAnalysis,
  } = useResources();

  const [customPrompt, setCustomPrompt] = useState("");
  const [analysisType, setAnalysisType] = useState({
    value: "comprehensive",
    label: "Comprehensive Analysis",
  });
  const [bedrockRegion, setBedrockRegion] = useState({
    value: "us-east-1",
    label: "US East (N. Virginia) - us-east-1",
  });
  const [timeElapsed, setTimeElapsed] = useState(0);
  const [estimatedTime, setEstimatedTime] = useState("15-30 minutes");
  const [showCompletionAlert, setShowCompletionAlert] = useState(false);

  const analysisTypeOptions = [
    { value: "comprehensive", label: "Comprehensive Analysis" },
    { value: "security", label: "Security Analysis" },
    { value: "cost", label: "Cost Optimization" },
    { value: "performance", label: "Performance Analysis" },
  ];

  const bedrockRegionOptions = [
    { value: "us-east-1", label: "US East (N. Virginia) - us-east-1" },
    { value: "us-east-2", label: "US East (Ohio) - us-east-2" },
    { value: "us-west-2", label: "US West (Oregon) - us-west-2" },
    { value: "eu-central-1", label: "Europe (Frankfurt) - eu-central-1" },
    { value: "eu-west-1", label: "Europe (Ireland) - eu-west-1" },
    { value: "eu-west-3", label: "Europe (Paris) - eu-west-3" },
  ];

  // Timer for elapsed time based on analysis start time
  useEffect(() => {
    let interval;
    if (isAnalyzing && analysisStartTime) {
      interval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - analysisStartTime) / 1000);
        setTimeElapsed(elapsed);

        // Update estimated time based on elapsed time
        if (elapsed > 1800) {
          // 30 minutes
          setEstimatedTime("Analysis taking longer than expected...");
        } else if (elapsed > 1200) {
          // 20 minutes
          setEstimatedTime("Should complete within 10 minutes");
        }
      }, 1000);
    } else {
      setTimeElapsed(0);
      setEstimatedTime("15-30 minutes");
    }
    return () => clearInterval(interval);
  }, [isAnalyzing, analysisStartTime]);

  // Show completion alert when analysis finishes
  useEffect(() => {
    if (!isAnalyzing && analysisResult && !showCompletionAlert) {
      setShowCompletionAlert(true);
      // Auto-hide the completion alert after 10 seconds
      const timer = setTimeout(() => {
        setShowCompletionAlert(false);
      }, 10000);
      return () => clearTimeout(timer);
    }
  }, [isAnalyzing, analysisResult, showCompletionAlert]);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  const handleAnalysis = async () => {
    const result = await startAnalysis({
      analysisType: analysisType.value,
      customPrompt: customPrompt,
      bedrockRegion: bedrockRegion.value,
    });

    if (!result.success && result.message) {
      console.log(result.message);
    }
  };

  const downloadReport = () => {
    if (!analysisResult?.report_markdown) return;

    const blob = new Blob([analysisResult.report_markdown], {
      type: "text/markdown",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aws_infrastructure_analysis_${
      new Date().toISOString().split("T")[0]
    }.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (!hasScanned) {
    return (
      <Container>
        <Alert type="warning" header="Infrastructure Scan Required">{/* # nosemgrep: jsx-not-internationalized */}
          Please complete the infrastructure scan first before running the
          analysis. Go to the Resources Report page to scan your AWS
          infrastructure.
        </Alert>
      </Container>
    );
  }

  return (
    <SpaceBetween size="l">
      <Header
        variant="h1"
        description="Generate comprehensive AI-powered analysis of your AWS infrastructure"
        actions={
          <SpaceBetween direction="horizontal" size="xs">
            {isAnalyzing && (
              <Button onClick={cancelAnalysis} iconName="close">{/* # nosemgrep: jsx-not-internationalized */}
                Cancel Analysis
              </Button>
            )}
            {analysisResult && (
              <Button onClick={resetAnalysis} iconName="refresh">{/* # nosemgrep: jsx-not-internationalized */}
                New Analysis
              </Button>
            )}
            <Button
              variant="primary"
              disabled={isAnalyzing || !bedrockRegion.value}
              onClick={handleAnalysis}
              loading={isAnalyzing}
            >
              {isAnalyzing ? "Analyzing..." : "Generate Analysis"}
            </Button>
          </SpaceBetween>
        }
      >{/* # nosemgrep: jsx-not-internationalized */}
        Infrastructure Analysis
      </Header>

      {/* Prerequisites */}
      <Container>
        <Alert type="info" header="Prerequisites">
          <SpaceBetween size="s">
            <div>
              <strong>{/* # nosemgrep: jsx-not-internationalized */}Amazon Bedrock Claude Model Required:</strong>
            </div>
            <ul style={{ marginLeft: "20px", marginBottom: "10px" }}>
              <li>{/* # nosemgrep: jsx-not-internationalized */}Ensure Amazon Bedrock Claude 3.7 Sonnet model is enabled in your selected region</li>
              <li>{/* # nosemgrep: jsx-not-internationalized */}Your AWS credentials must have access to Amazon Bedrock service</li>
              <li>{/* # nosemgrep: jsx-not-internationalized */}Claude 3.7 Sonnet model must be available and activated in the Bedrock console</li>
            </ul>
            <div>
              <strong>{/* # nosemgrep: jsx-not-internationalized */}Supported Regions:</strong> US East (N. Virginia), US West (Oregon), Asia Pacific (Singapore), Asia Pacific (Tokyo), Europe (Frankfurt), Europe (Ireland), Europe (Paris)
            </div>
          </SpaceBetween>
        </Alert>
      </Container>

      {/* Configuration Form */}
      <Container>
        <Form>
          <SpaceBetween size="l">
            <FormField
              label="Analysis Type"
              description="Select the type of analysis you want to perform"
            >
              <Select
                selectedOption={analysisType}
                onChange={({ detail }) =>
                  setAnalysisType(detail.selectedOption)
                }
                options={analysisTypeOptions}
                disabled={isAnalyzing}
              />
            </FormField>

            <FormField
              label="Bedrock Region"
              description="Required: Select the AWS region where Amazon Bedrock Claude 3.7 Sonnet model is enabled"
            >
              <Select
                selectedOption={bedrockRegion}
                onChange={({ detail }) =>
                  setBedrockRegion(detail.selectedOption)
                }
                options={bedrockRegionOptions}
                disabled={isAnalyzing}
                placeholder="Select a Bedrock region..."
              />
            </FormField>

            <FormField
              label="Custom Prompt (Optional)"
              description="Add specific instructions or focus areas for the analysis"
            >
              <Textarea
                value={customPrompt}
                onChange={({ detail }) => setCustomPrompt(detail.value)}
                rows={4}
                disabled={isAnalyzing}
                placeholder="Example: Focus on compute resources and their security posture, Check compliance with best practices"
              />
            </FormField>
          </SpaceBetween>
        </Form>
      </Container>

      {/* Infrastructure Summary */}
      <Container>
        <Header variant="h2">{/* # nosemgrep: jsx-not-internationalized */}Infrastructure Summary</Header>
        <ColumnLayout columns={4} variant="text-grid">
          <div>
            <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Account ID</Box>
            <div>{resources?.account_id || "Unknown"}</div>
          </div>
          <div>
            <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Regions Scanned</Box>
            <div>{resources?.regions_scanned?.length || 0}</div>
          </div>
          <div>
            <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Services</Box>
            <div>{resources?.services_scanned?.length || 0}</div>
          </div>
          <div>
            <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Resource Groups</Box>
            <div>{resources?.resources?.length || 0}</div>
          </div>
        </ColumnLayout>
      </Container>

      {/* Analysis Progress */}
      {isAnalyzing && (
        <Container>
          <Header variant="h2">{/* # nosemgrep: jsx-not-internationalized */}Analysis in Progress</Header>
          <SpaceBetween size="m">
            <Alert type="info" header="AI Analysis Running">{/* # nosemgrep: jsx-not-internationalized */}
              Your infrastructure is being analyzed using Amazon Bedrock. This
              process typically takes {estimatedTime}. Please keep this page
              open and do not navigate away.
            </Alert>

            <ColumnLayout columns={3} variant="text-grid">
              <div>
                <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Time Elapsed</Box>
                <div>{formatTime(timeElapsed)}</div>
              </div>
              <div>
                <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Estimated Total Time</Box>
                <div>{estimatedTime}</div>
              </div>
              <div>
                <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Status</Box>
                <StatusIndicator type="in-progress">
                  <Spinner />{/* # nosemgrep: jsx-not-internationalized */} Processing
                </StatusIndicator>
              </div>
            </ColumnLayout>

            <ProgressBar
              value={analysisProgress}
              additionalInfo="Analyzing infrastructure configurations..."
              description="Progress is estimated based on typical analysis time"
            />
          </SpaceBetween>
        </Container>
      )}

      {/* Completion Alert */}
      {showCompletionAlert && analysisResult && (
        <Alert
          type="success"
          header="Analysis Complete!"
          dismissible
          onDismiss={() => setShowCompletionAlert(false)}
        >{/* # nosemgrep: jsx-not-internationalized */}
          Your AWS infrastructure analysis has been completed successfully in{" "}
          {analysisResult.total_processing_time_minutes?.toFixed(1) || "N/A"}{" "}
          minutes. The comprehensive report is now available below.
        </Alert>
      )}

      {/* Error Display */}
      {analysisError && (
        <Alert type="error" header="Analysis Failed">
          {analysisError}
        </Alert>
      )}

      {/* Analysis Results */}
      {analysisResult && (
        <Container>
          <Header
            variant="h2"
            actions={
              <Button onClick={downloadReport} iconName="download">{/* # nosemgrep: jsx-not-internationalized */}
                Download Report
              </Button>
            }
          >{/* # nosemgrep: jsx-not-internationalized */}
            Analysis Results
          </Header>

          <SpaceBetween size="m">
            <ColumnLayout columns={4} variant="text-grid">
              <div>
                <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Analysis Type</Box>
                <Badge color="blue">{analysisResult.analysis_type}</Badge>
              </div>
              <div>
                <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Model Used</Box>
                <Badge color="green">
                  {analysisResult.model_used?.split(".")[1] || "Claude 3.7 Sonnet"}
                </Badge>
              </div>
              <div>
                <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Report Size</Box>
                <div>
                  {Math.round(
                    (analysisResult.report_markdown?.length || 0) / 1024
                  )}{" "}
                  KB
                </div>
              </div>
              <div>
                <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Processing Time</Box>
                <div>
                  {analysisResult.total_processing_time_minutes?.toFixed(1) ||
                    "N/A"}{" "}
                  min
                </div>
              </div>
            </ColumnLayout>

            {analysisResult.chunking_used && (
              <Alert type="info" header="Large Dataset Processing">{/* # nosemgrep: jsx-not-internationalized */}
                Your infrastructure data was processed using intelligent
                chunking (
                {analysisResult.chunk_summary?.total_chunks || "multiple"}{" "}
                chunks) for optimal analysis quality.
              </Alert>
            )}

            <Tabs
              tabs={[
                {
                  label: "Analysis Report",
                  id: "report",
                  content: (
                    <Container>
                      <div className="markdown-content">
                        <ReactMarkdown>
                          {(() => {
                            const content =
                              analysisResult.report_markdown || "";
                            return content.replace(/\\n/g, "\n");
                          })()}
                        </ReactMarkdown>
                      </div>
                    </Container>
                  ),
                },
                {
                  label: "Processing Summary",
                  id: "summary",
                  content: (
                    <Container>
                      <SpaceBetween size="m">
                        <ColumnLayout columns={2} variant="text-grid">
                          <div>
                            <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Account ID</Box>
                            <div>
                              {analysisResult.metadata?.account_id || "Unknown"}
                            </div>
                          </div>
                          <div>
                            <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Scan Time</Box>
                            <div>
                              {analysisResult.metadata?.scan_time || "Unknown"}
                            </div>
                          </div>
                          <div>
                            <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Total Resources</Box>
                            <div>
                              {analysisResult.metadata?.total_resources || 0}
                            </div>
                          </div>
                          <div>
                            <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}
                              Services Analyzed
                            </Box>
                            <div>
                              {analysisResult.metadata?.services_analyzed || 0}
                            </div>
                          </div>
                        </ColumnLayout>

                        {analysisResult.chunk_summary && (
                          <Box>
                            <Header variant="h4">{/* # nosemgrep: jsx-not-internationalized */}
                              Chunk Processing Details
                            </Header>
                            <ColumnLayout columns={2} variant="text-grid">
                              {Object.entries(
                                analysisResult.chunk_summary.chunks || {}
                              ).map(([key, chunk]) => (
                                <div key={key}>
                                  <Box variant="awsui-key-label">
                                    {key.replace("_", " ").toUpperCase()}
                                  </Box>
                                  <div>{/* # nosemgrep: jsx-not-internationalized */}
                                    {chunk.services} services,{" "}
                                    {chunk.total_resources} resources
                                    <br />
                                    <small style={{ color: "#666" }}>
                                      {chunk.focus_area}
                                    </small>
                                  </div>
                                </div>
                              ))}
                            </ColumnLayout>
                          </Box>
                        )}

                        {analysisResult.file_metadata && (
                          <Box>
                            <Header variant="h4">{/* # nosemgrep: jsx-not-internationalized */}File Information</Header>
                            <ColumnLayout columns={3} variant="text-grid">
                              <div>
                                <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Filename</Box>
                                <div>
                                  {analysisResult.file_metadata.filename}
                                </div>
                              </div>
                              <div>
                                <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}File Size</Box>
                                <div>{/* # nosemgrep: jsx-not-internationalized */}
                                  {analysisResult.file_metadata.file_size_mb} MB
                                </div>
                              </div>
                              <div>
                                <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}
                                  Upload Method
                                </Box>
                                <div>
                                  {analysisResult.file_metadata.upload_method}
                                </div>
                              </div>
                            </ColumnLayout>
                          </Box>
                        )}
                      </SpaceBetween>
                    </Container>
                  ),
                },
              ]}
            />
          </SpaceBetween>
        </Container>
      )}
    </SpaceBetween>
  );
};

export default InfrastructureAnalysis;
