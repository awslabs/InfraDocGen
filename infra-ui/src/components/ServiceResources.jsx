// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { useState } from 'react';
import {
  Container,
  SpaceBetween,
  ExpandableSection
} from '@cloudscape-design/components';
import ResourceDetails from './ResourceDetails';

const ServiceResources = ({ serviceData }) => {
  const [expanded, setExpanded] = useState(false);
  
  // AWS color palette
  const awsColors = {
    primary: '#232F3E',    // AWS Navy
    secondary: '#FF9900',  // AWS Orange
    accent: '#0073BB',     // AWS Blue
    success: '#1D8102'     // AWS Green
  };

  // Ensure resources is an array
  const resources = Array.isArray(serviceData.resources) ? serviceData.resources : [];

  return (
    <ExpandableSection
      variant="container"
      headerText={
        <span>
          <span style={{ color: awsColors.accent }}>{serviceData.service?.toUpperCase()} ({serviceData.region})</span>
          {' - '}
          <span style={{ color: awsColors.success }}>{serviceData.subservice} ({serviceData.resource_count})</span>
        </span>
      }
      expanded={expanded}
      onChange={() => setExpanded(!expanded)}
    >
      {expanded && (
        <SpaceBetween size="l">
          {resources.map((resource, index) => (
            <Container key={index}>
              <ResourceDetails resource={resource} />
            </Container>
          ))}
        </SpaceBetween>
      )}
    </ExpandableSection>
  );
};

export default ServiceResources;