// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import {
  Container,
  SpaceBetween,
  Alert,
  TextContent,
  Box,
} from "@cloudscape-design/components";
import { useResources } from "../context/ResourceContext";
import ServiceGroup from "./ServiceGroup";

const ResourcesReport = () => {
  const { resources, error } = useResources();

  if (error) {
    return (
      <Alert type="error" header="Error scanning resources">
        {error}
      </Alert>
    );
  }

  if (!resources) {
    return (
      <Container>
        <Box textAlign="center" padding={{ top: "l" }}>
          <TextContent>
            <h2>{/* # nosemgrep: jsx-not-internationalized */}No Resources Scanned</h2>
            <p>{/* # nosemgrep: jsx-not-internationalized */}
              Click the "Start Scanning" button above to scan your AWS
              resources.
            </p>
          </TextContent>
        </Box>
      </Container>
    );
  }

  // Group resources by service type and subservice
  const serviceGroups = {};

  if (resources.resources) {
    resources.resources.forEach((serviceData) => {
      const serviceName = serviceData.service;
      const subservice = serviceData.subservice;

      if (!serviceGroups[serviceName]) {
        serviceGroups[serviceName] = {};
      }

      if (!serviceGroups[serviceName][subservice]) {
        serviceGroups[serviceName][subservice] = [];
      }

      serviceGroups[serviceName][subservice].push(serviceData);
    });
  }

  return (
    <Container>
      <TextContent>
        <h1>{/* # nosemgrep: jsx-not-internationalized */}AWS Infrastructure Report</h1>
        <p>{/* # nosemgrep: jsx-not-internationalized */}Account ID: {resources.account_id}</p>
        <p>{/* # nosemgrep: jsx-not-internationalized */}Scan Time: {resources.scan_time}</p>
      </TextContent>

      <SpaceBetween size="l">
        {Object.entries(serviceGroups).map(
          ([serviceName, subservices], index) => (
            <ServiceGroup
              key={index}
              serviceName={serviceName}
              subservices={subservices}
            />
          )
        )}
      </SpaceBetween>
    </Container>
  );
};

export default ResourcesReport;
