// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { useState } from "react";
import {
  Container,
  SpaceBetween,
  ExpandableSection,
  Button,
  Box,
  StatusIndicator,
} from "@cloudscape-design/components";
import ResourceDetails from "./ResourceDetails";

const ServiceGroup = ({ serviceName, subservices }) => {
  const [expanded, setExpanded] = useState(false);
  const [expandedSubservices, setExpandedSubservices] = useState({});
  const [resourceLimits, setResourceLimits] = useState({});

  const RESOURCES_PER_PAGE = 50;

  // AWS color palette
  const awsColors = {
    primary: "#232F3E", // AWS Navy
    secondary: "#FF9900", // AWS Orange
    accent: "#0073BB", // AWS Blue
    success: "#1D8102", // AWS Green
  };

  const toggleSubservice = (subservice) => {
    setExpandedSubservices((prev) => ({
      ...prev,
      [subservice]: !prev[subservice],
    }));

    // Reset resource limit when toggling
    if (!expandedSubservices[subservice]) {
      setResourceLimits((prev) => ({
        ...prev,
        [subservice]: RESOURCES_PER_PAGE,
      }));
    }
  };

  // Function to combine and sort resources from all regions
  const combineAndSortResources = (regionItems) => {
    // Flatten all resources from all regions into a single array
    // and add region as a property to each resource
    const allResources = regionItems.flatMap((regionData) =>
      regionData.resources.map((resource) => ({
        ...resource,
        Region: regionData.region, // Add region as a property
      }))
    );

    // Sort resources by region
    return allResources.sort((a, b) => a.Region.localeCompare(b.Region));
  };

  // Function to load more resources
  const loadMoreResources = (subservice) => {
    setResourceLimits((prev) => ({
      ...prev,
      [subservice]:
        (prev[subservice] || RESOURCES_PER_PAGE) + RESOURCES_PER_PAGE,
    }));
  };

  return (
    <ExpandableSection
      variant="container"
      headerText={
        <span style={{ color: awsColors.accent }}>
          {serviceName.toUpperCase()}
        </span>
      }
      expanded={expanded}
      onChange={() => setExpanded(!expanded)}
    >
      {expanded && (
        <SpaceBetween size="l">
          {Object.entries(subservices).map(([subservice, regionItems]) => {
            const allResources = combineAndSortResources(regionItems);
            const totalCount = allResources.length;
            const limit = resourceLimits[subservice] || RESOURCES_PER_PAGE;
            const visibleResources = allResources.slice(0, limit);
            const hasMore = totalCount > limit;

            return (
              <ExpandableSection
                key={subservice}
                variant="container"
                headerText={
                  <span style={{ color: awsColors.secondary }}>
                    {subservice} ({totalCount})
                  </span>
                }
                expanded={expandedSubservices[subservice]}
                onChange={() => toggleSubservice(subservice)}
              >
                {expandedSubservices[subservice] && (
                  <>
                    {totalCount > RESOURCES_PER_PAGE && (
                      <Box padding="s">
                        <StatusIndicator type="info">{/* # nosemgrep: jsx-not-internationalized */}
                          Showing {Math.min(limit, totalCount)} of {totalCount}{" "}
                          resources
                        </StatusIndicator>
                      </Box>
                    )}
                    <SpaceBetween size="s">
                      {visibleResources.map((resource, resIndex) => (
                        <Container key={resIndex}>
                          <ResourceDetails resource={resource} />
                        </Container>
                      ))}
                      {hasMore && (
                        <Box textAlign="center" padding="s">
                          <Button onClick={() => loadMoreResources(subservice)}>{/* # nosemgrep: jsx-not-internationalized */}
                            Load more resources ({limit} of {totalCount} shown)
                          </Button>
                        </Box>
                      )}
                    </SpaceBetween>
                  </>
                )}
              </ExpandableSection>
            );
          })}
        </SpaceBetween>
      )}
    </ExpandableSection>
  );
};

export default ServiceGroup;
