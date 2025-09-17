// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  Container,
  Header,
  SpaceBetween,
  Button,
  Alert,
  Box,
  ColumnLayout,
  Badge,
  Select,
  FormField,
  Toggle,
  Cards,
  Spinner,
  ProgressBar,
  StatusIndicator,
  Modal,
} from "@cloudscape-design/components";
import ReactFlow, {
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  ConnectionLineType,
} from "reactflow";
import "reactflow/dist/style.css";
import { useResources } from "../context/ResourceContext";
import "./ResourceDependencies.css";

// Suppress ResizeObserver errors globally
const originalError = console.error;
console.error = (...args) => {
  if (
    typeof args[0] === "string" &&
    (args[0].includes(
      "ResizeObserver loop completed with undelivered notifications"
    ) ||
      args[0].includes("ResizeObserver loop limit exceeded"))
  ) {
    return;
  }
  originalError.apply(console, args);
};

// Also suppress window errors
window.addEventListener("error", (e) => {
  if (e.message && e.message.includes("ResizeObserver")) {
    e.preventDefault();
    return false;
  }
});

// Suppress unhandled promise rejections related to ResizeObserver
window.addEventListener("unhandledrejection", (e) => {
  if (
    e.reason &&
    e.reason.message &&
    e.reason.message.includes("ResizeObserver")
  ) {
    e.preventDefault();
    return false;
  }
});

const ResourceDependencies = () => {
  const {
    resources,
    hasScanned,
    // Dependency analysis state from context
    isAnalyzingDependencies,
    dependencyResult,
    dependencyError,
    dependencyProgress,
    dependencyStartTime,
    startDependencyAnalysis,
  } = useResources();

  const [dependencies, setDependencies] = useState(null);
  const [selectedService, setSelectedService] = useState({
    value: "all",
    label: "All Services",
  });
  const [showLabels, setShowLabels] = useState(true);
  const [edgeVisibilityMode] = useState("normal"); // normal, elevated, bundled

  const [serviceOptions, setServiceOptions] = useState([
    { value: "all", label: "All Services" },
  ]);

  const bedrockRegionOptions = [
    { value: "us-east-1", label: "US East (N. Virginia) - us-east-1" },
    { value: "us-east-2", label: "US East (Ohio) - us-east-2" },
    { value: "us-west-2", label: "US West (Oregon) - us-west-2" },
    { value: "eu-central-1", label: "Europe (Frankfurt) - eu-central-1" },
    { value: "eu-west-1", label: "Europe (Ireland) - eu-west-1" },
    { value: "eu-west-3", label: "Europe (Paris) - eu-west-3" },
  ];

  // Local UI state
  const [timeElapsed, setTimeElapsed] = useState(0);
  const [estimatedTime, setEstimatedTime] = useState("15-30 minutes");
  const [showCompletionAlert, setShowCompletionAlert] = useState(false);

  // React Flow state (moved before callbacks to avoid initialization issues)
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  // Selected resource for graph display
  const [selectedResourceId, setSelectedResourceId] = useState(null);

  // Fullscreen state for dependency graph
  const [isFullscreen, setIsFullscreen] = useState(false);

  // Bedrock region configuration
  const [bedrockRegion, setBedrockRegion] = useState({
    value: "us-east-1",
    label: "US East (N. Virginia) - us-east-1",
  });

  // Store user-moved node positions to preserve them across filter changes (using ref to avoid re-renders)
  const nodePositionsRef = useRef(new Map());

  // Custom onNodesChange handler that preserves positions
  const handleNodesChange = useCallback(
    (changes) => {
      // Update the positions map when nodes are dragged (using ref to avoid re-renders)
      changes.forEach((change) => {
        if (change.type === "position" && change.position) {
          nodePositionsRef.current.set(change.id, change.position);
        }
      });

      // Apply the changes to the nodes
      onNodesChange(changes);
    },
    [onNodesChange]
  );

  // Handle resource selection from cards to show graph
  const handleResourceSelection = useCallback(
    (resourceId) => {
      // Clear existing graph first to prevent ResizeObserver conflicts
      setNodes([]);
      setEdges([]);

      // Use requestAnimationFrame to ensure DOM is updated before setting new graph
      requestAnimationFrame(() => {
        setSelectedResourceId(resourceId);

        if (!dependencies || !dependencies.dependencyMap) {
          return;
        }

        // Get dependencies for the selected resource
        const resourceDependencies =
          dependencies.dependencyMap.get(resourceId) || [];

        // Create nodes for the selected resource and its dependencies
        const graphNodes = [];
        const graphEdges = [];

        // Add the main resource node (center position)
        const mainResource = dependencies.resourceMap.get(resourceId);
        if (mainResource) {
          graphNodes.push({
            id: resourceId,
            type: "default",
            position: { x: 300, y: 200 }, // Center position
            data: {
              label: showLabels
                ? getResourceLabel(mainResource)
                : mainResource.subservice,
              resourceInfo: mainResource,
            },
            style: getNodeStyle(mainResource.service),
            className: `resource-node resource-${mainResource.service}`,
          });
        }

        // Group dependencies by target to combine multiple edges into single edge with comma-separated labels
        const targetGroups = new Map();

        // Group dependencies by target
        resourceDependencies.forEach((dep) => {
          if (!targetGroups.has(dep.target)) {
            targetGroups.set(dep.target, []);
          }
          targetGroups.get(dep.target).push(dep);
        });

        // Create single edge per target with combined labels
        let targetIndex = 0;
        targetGroups.forEach((deps, target) => {
          const isExternal = !dependencies.resourceMap.has(target);

          // Combine all action types for this target
          const actionTypes = deps.map((dep) => dep.type);
          const combinedLabel = actionTypes.join(", ");

          // Use the first dependency's style as base
          const edgeStyle = getEdgeStyle(deps[0].type, isExternal);

          // Create single edge with combined label using improved routing
          graphEdges.push({
            id: `${resourceId}-${target}-combined`,
            source: resourceId,
            target: target,
            type: "step", // Use step routing for better node avoidance
            animated: isExternal,
            style: {
              ...edgeStyle,
              strokeWidth: 4, // Thicker edges for better visibility
              strokeOpacity: 0.9,
            },
            label: combinedLabel, // Combined action types separated by commas
            labelStyle: {
              fontSize: 11,
              fontWeight: 600,
              fill: edgeStyle.stroke,
              backgroundColor: "rgba(255, 255, 255, 0.95)",
              padding: "4px 8px",
              borderRadius: "4px",
              maxWidth: "200px",
              wordWrap: "break-word",
              border: "1px solid #ccc",
              boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
            },
            data: {
              actionTypes: actionTypes,
              totalActions: actionTypes.length,
            },
            // Add markerEnd for better visibility
            markerEnd: {
              type: "arrowclosed",
              width: 15,
              height: 15,
              color: edgeStyle.stroke,
            },
          });

          targetIndex++;
        });

        // Create nodes for each unique target
        targetGroups.forEach((deps, target) => {
          const position = {
            x:
              300 +
              Math.cos((targetIndex * 2 * Math.PI) / targetGroups.size) * 400, // Increased radius for longer edges
            y:
              200 +
              Math.sin((targetIndex * 2 * Math.PI) / targetGroups.size) * 400, // Increased radius for longer edges
          };

          let dependencyNode;
          if (dependencies.resourceMap.has(target)) {
            // Internal resource node
            const resourceInfo = dependencies.resourceMap.get(target);
            dependencyNode = {
              id: target,
              type: "default",
              position: position,
              data: {
                label: showLabels
                  ? getResourceLabel(resourceInfo)
                  : resourceInfo.subservice,
                resourceInfo,
              },
              style: getNodeStyle(resourceInfo.service),
              className: `resource-node resource-${resourceInfo.service}`,
            };
          } else {
            // External service node
            const externalNode = {
              id: target,
              service: getServiceFromTarget(target),
              region: "external",
              subservice: "External Service",
              type: "external",
              resource: { id: target },
            };

            dependencyNode = {
              id: target,
              type: "default",
              position: position,
              data: {
                label: showLabels
                  ? getExternalNodeLabel(externalNode)
                  : externalNode.subservice,
                resourceInfo: externalNode,
              },
              style: getNodeStyle("external"),
              className: `resource-node resource-external`,
            };
          }

          graphNodes.push(dependencyNode);
          targetIndex++;
        });

        // Update the graph with only this resource and its dependencies
        // Use another requestAnimationFrame to ensure smooth transition
        requestAnimationFrame(() => {
          setNodes(graphNodes);
          setEdges(graphEdges);

          // Auto-scroll to the graph section after a short delay to ensure it's rendered
          setTimeout(() => {
            const graphElement = document.querySelector(
              '[data-testid="dependency-graph"]'
            );
            if (graphElement) {
              graphElement.scrollIntoView({
                behavior: "smooth",
                block: "start",
                inline: "nearest",
              });
            }
          }, 200);
        });
      });
    },
    [dependencies, showLabels, setNodes, setEdges]
  );

  // Clear selected resource and hide graph
  const clearSelection = useCallback(() => {
    setSelectedResourceId(null);
    setNodes([]);
    setEdges([]);
  }, [setNodes, setEdges]);

  // Create React Flow nodes with automatic layout to prevent edge overlaps
  const createFlowNodes = useCallback(
    (resourceMap, serviceFilter, dependencyMap) => {
      const nodes = [];
      const filteredResources = [];
      const dependencyTargets = new Set(); // Track dependency targets to include

      // First, collect all resources that match the filter
      resourceMap.forEach((resourceInfo, resourceId) => {
        if (serviceFilter !== "all" && resourceInfo.service !== serviceFilter) {
          return;
        }
        filteredResources.push({ id: resourceId, info: resourceInfo });

        // When filtering by specific service, also collect dependency targets
        if (serviceFilter !== "all" && dependencyMap) {
          const deps = dependencyMap.get(resourceId) || [];
          deps.forEach((dep) => {
            dependencyTargets.add(dep.target);
          });
        }
      });

      // When filtering by specific service, also include dependency targets
      if (serviceFilter !== "all" && dependencyMap) {
        dependencyTargets.forEach((targetId) => {
          const targetResource = resourceMap.get(targetId);
          if (
            targetResource &&
            !filteredResources.find((r) => r.id === targetId)
          ) {
            // Include internal resources from other services
            filteredResources.push({
              id: targetId,
              info: targetResource,
              isDependencyTarget: true,
            });
          } else if (!targetResource) {
            // Create external node for targets that don't exist in resourceMap
            const externalNode = {
              id: targetId,
              service: getServiceFromTarget(targetId),
              region: "external",
              subservice: "External Service",
              type: "external",
              resource: { id: targetId },
            };
            filteredResources.push({
              id: targetId,
              info: externalNode,
              isDependencyTarget: true,
              isExternal: true,
            });
          }
        });
      }

      // Use a force-directed layout with large spacing to prevent edge overlaps
      const centerX = 600;
      const centerY = 400;

      if (filteredResources.length <= 1) {
        // Single node - place in center
        filteredResources.forEach((resource) => {
          nodes.push({
            id: resource.id,
            type: "default",
            position: { x: centerX, y: centerY },
            data: {
              label: showLabels
                ? getResourceLabel(resource.info)
                : resource.info.subservice,
              resourceInfo: resource.info,
            },
            style: {
              ...getNodeStyle(resource.info.service || resource.info.type),
              zIndex: 10,
              ...(resource.isDependencyTarget && !resource.isExternal
                ? { opacity: 0.7 }
                : {}),
            },
            className: `resource-node resource-${
              resource.info.service || resource.info.type
            }`,
          });
        });
      } else if (filteredResources.length <= 6) {
        // Small number - use circular layout with large radius
        const radius = 300;
        filteredResources.forEach((resource, index) => {
          const angle = (index * 2 * Math.PI) / filteredResources.length;
          const x = centerX + radius * Math.cos(angle);
          const y = centerY + radius * Math.sin(angle);

          nodes.push({
            id: resource.id,
            type: "default",
            position: { x, y },
            data: {
              label: showLabels
                ? getResourceLabel(resource.info)
                : resource.info.subservice,
              resourceInfo: resource.info,
            },
            style: {
              ...getNodeStyle(resource.info.service || resource.info.type),
              zIndex: 10,
              ...(resource.isDependencyTarget && !resource.isExternal
                ? { opacity: 0.7 }
                : {}),
            },
            className: `resource-node resource-${
              resource.info.service || resource.info.type
            }`,
          });
        });
      } else {
        // Large number - use grid layout with maximum spacing
        const cols = Math.ceil(Math.sqrt(filteredResources.length));
        const spacing = { x: 400, y: 300 }; // Very large spacing

        filteredResources.forEach((resource, index) => {
          const col = index % cols;
          const row = Math.floor(index / cols);
          const x = col * spacing.x + 100; // Add offset
          const y = row * spacing.y + 100; // Add offset

          nodes.push({
            id: resource.id,
            type: "default",
            position: { x, y },
            data: {
              label: showLabels
                ? getResourceLabel(resource.info)
                : resource.info.subservice,
              resourceInfo: resource.info,
            },
            style: {
              ...getNodeStyle(resource.info.service || resource.info.type),
              zIndex: 10,
              ...(resource.isDependencyTarget && !resource.isExternal
                ? { opacity: 0.7 }
                : {}),
            },
            className: `resource-node resource-${
              resource.info.service || resource.info.type
            }`,
          });
        });
      }

      return nodes;
    },
    [showLabels]
  );

  // Create React Flow edges
  const createFlowEdges = useCallback(
    (dependencyMap, resourceMap, serviceFilter) => {
      const edges = [];
      const externalNodes = new Map(); // Track external dependencies

      dependencyMap.forEach((dependencies, sourceId) => {
        const sourceResource = resourceMap.get(sourceId);

        dependencies.forEach((dep, index) => {
          const targetResource = resourceMap.get(dep.target);

          // For service filtering, show edges based on what nodes are visible
          if (serviceFilter !== "all") {
            // When filtering by specific service, only show edges where source matches the filter
            const sourceMatchesFilter =
              sourceResource?.service === serviceFilter;

            // Skip edge if source doesn't match the filter
            if (!sourceMatchesFilter) {
              return;
            }

            // For filtered view, show ALL edges from matching sources:
            // - To other resources in the same service (internal)
            // - To external services (provides important context)
            // - To resources in different services (cross-service dependencies)

            // Don't filter out any targets - show all dependencies of the filtered resources
          }

          // Create edge if source exists (target can be external)
          if (sourceResource) {
            // If target doesn't exist in our resource map, create an external node
            if (!targetResource) {
              // Create external node for services like cloudtrail.amazonaws.com, etc.
              const externalNodeId = dep.target;
              if (!externalNodes.has(externalNodeId)) {
                externalNodes.set(externalNodeId, {
                  id: externalNodeId,
                  service: getServiceFromTarget(dep.target),
                  region: "external",
                  subservice: "External Service",
                  type: "external",
                  resource: { id: externalNodeId },
                });
              }
            }

            // Show edges for matching sources or targets with improved routing
            const edge = {
              id: `${sourceId}-${dep.target}-${index}`,
              source: sourceId,
              target: dep.target,
              type: "step", // Use step routing to avoid nodes better
              animated: !targetResource, // Animate external connections
              style: {
                ...getEdgeStyle(dep.type, !targetResource),
                strokeWidth: 4, // Thicker edges for better visibility
                strokeOpacity: 0.9,
              },
              label:
                dep.type.length > 20
                  ? dep.type.substring(0, 17) + "..."
                  : dep.type,
              labelStyle: {
                fontSize: 11,
                fontWeight: 600,
                backgroundColor: "rgba(255, 255, 255, 0.95)",
                padding: "4px 8px",
                borderRadius: "4px",
                border: "1px solid #ccc",
                boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
              },
              markerEnd: {
                type: "arrowclosed",
                width: 15,
                height: 15,
                color: getEdgeStyle(dep.type, !targetResource).stroke,
              },
            };

            edges.push(edge);
          }
        });
      });

      return { edges, externalNodes };
    },
    []
  );

  // Parse markdown content to extract resource dependencies
  const parseMarkdownContent = useCallback((markdownContent) => {
    const resourcesData = [];
    const connections = [];

    try {
      // Split content by resource sections (### resource_id)
      const resourceSections = markdownContent.split(/### ([^\n]+)/);

      for (let i = 1; i < resourceSections.length; i += 2) {
        const resourceId = resourceSections[i].trim();
        const resourceContent = resourceSections[i + 1];

        if (!resourceContent) continue;

        // Extract resource details with more flexible matching
        const typeMatch = resourceContent.match(/- \*\*Type\*\*:\s*([^\n]+)/);
        const serviceMatch = resourceContent.match(
          /- \*\*Service\*\*:\s*([^\n]+)/
        );
        const regionMatch = resourceContent.match(
          /- \*\*Region\*\*:\s*([^\n]+)/
        );

        // Just use what's provided in the markdown, no ARN parsing
        let service = serviceMatch ? serviceMatch[1].trim() : "unknown";

        const resource = {
          id: resourceId,
          type: typeMatch ? typeMatch[1].trim() : "Unknown",
          service: service,
          region: regionMatch ? regionMatch[1].trim() : "unknown",
        };

        resourcesData.push(resource);

        // Extract connections with improved parsing
        const connectionsMatch = resourceContent.match(
          /- \*\*Connections\*\*:\s*([\s\S]*?)(?=\n### |$)/
        );
        if (connectionsMatch) {
          const connectionLines = connectionsMatch[1].split("\n");
          connectionLines.forEach((line) => {
            // Match patterns like "  - **target**: relationship"
            // Fixed regex to prevent ReDoS by limiting capture groups
            const connectionMatch = line.match(
              /\s*- \*\*([^*]{1,100})\*\*:\s*([^\n]{1,200})/
            );
            if (connectionMatch) {
              const targetId = connectionMatch[1].trim();
              const relationshipType = connectionMatch[2].trim();

              // Only add connection if target is not empty
              if (targetId && relationshipType) {
                connections.push({
                  source: resourceId,
                  target: targetId,
                  type: relationshipType,
                });
              }
            }
          });
        }
      }

      return { resources: resourcesData, connections };
    } catch (error) {
      console.error("Error parsing markdown content:", error);
      return { resources: [], connections: [] };
    }
  }, []);

  // Timer for elapsed time tracking
  useEffect(() => {
    let interval;
    if (isAnalyzingDependencies && dependencyStartTime) {
      interval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - dependencyStartTime) / 1000);
        setTimeElapsed(elapsed);

        // Update estimated time based on elapsed time
        if (elapsed > 1200) {
          // 20 minutes
          setEstimatedTime("Analysis taking longer than expected...");
        } else if (elapsed > 900) {
          // 15 minutes
          setEstimatedTime("Should complete within 5 minutes");
        } else if (elapsed > 600) {
          // 10 minutes
          setEstimatedTime("Should complete within 10 minutes");
        }
      }, 1000);
    } else {
      setTimeElapsed(0);
      setEstimatedTime("15-30 minutes");
    }
    return () => clearInterval(interval);
  }, [isAnalyzingDependencies, dependencyStartTime]);

  // Show completion alert when analysis finishes
  useEffect(() => {
    if (
      !isAnalyzingDependencies &&
      dependencies &&
      !showCompletionAlert &&
      dependencyStartTime
    ) {
      setShowCompletionAlert(true);
      // Auto-hide the completion alert after 10 seconds
      const timer = setTimeout(() => {
        setShowCompletionAlert(false);
      }, 10000);
      return () => clearTimeout(timer);
    }
  }, [
    isAnalyzingDependencies,
    dependencies,
    showCompletionAlert,
    dependencyStartTime,
  ]);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  // Process dependency result from context
  useEffect(() => {
    if (dependencyResult && dependencyResult.markdown_content) {
      // Parse the markdown content
      const { resources: parsedResources, connections } = parseMarkdownContent(
        dependencyResult.markdown_content
      );

      // Extract unique services from parsed resources and update service options
      const uniqueServices = [
        ...new Set(parsedResources.map((resource) => resource.service)),
      ];

      // Filter out invalid services (empty, null, undefined, or single characters that might be parsing errors)
      const validServices = uniqueServices.filter(
        (service) =>
          service &&
          service !== "unknown" &&
          service.length > 1 &&
          service.trim().length > 1
      );

      const dynamicServiceOptions = [
        { value: "all", label: "All Services" },
        ...validServices.sort().map((service) => ({
          value: service,
          label: service.toUpperCase(),
        })),
      ];
      setServiceOptions(dynamicServiceOptions);

      // Convert parsed data to the format expected by React Flow
      const resourceMap = new Map();
      const dependencyMap = new Map();

      // Create resource map from AI parsed resources - filter out unknown services
      parsedResources.forEach((resource) => {
        if (resource.service === "unknown") {
          return;
        }
        
        resourceMap.set(resource.id, {
          id: resource.id,
          service: resource.service,
          region: resource.region,
          subservice: resource.type,
          type: getResourceTypeFromService(resource.service),
          resource: resource,
        });
      });

      // If AI didn't provide enough resources, use original infrastructure data as fallback
      if (parsedResources.length === 0 && resources?.resources) {
        // This fallback is no longer needed since we're using markdown structure

        // Update service options based on original data
        const originalServices = [
          ...new Set(resources.resources.map((sg) => sg.service.toLowerCase())),
        ];
        const originalServiceOptions = [
          { value: "all", label: "All Services" },
          ...originalServices.sort().map((service) => ({
            value: service,
            label: service.toUpperCase(),
          })),
        ];
        setServiceOptions(originalServiceOptions);
      }

      // Create dependency map
      connections.forEach((connection) => {
        if (!dependencyMap.has(connection.source)) {
          dependencyMap.set(connection.source, []);
        }
        dependencyMap.get(connection.source).push({
          target: connection.target,
          type: connection.type,
        });
      });

      // If AI didn't provide enough connections, use local dependency detection as fallback
      if (connections.length === 0) {
        // Use local dependency detection for all resources
        resourceMap.forEach((resourceInfo, resourceId) => {
          const localDependencies = findResourceDependencies(
            resourceInfo,
            resourceMap
          );
          if (localDependencies.length > 0) {
            dependencyMap.set(resourceId, localDependencies);
          }
        });
      }

      // Convert to nodes and edges for React Flow
      const nodes = createFlowNodes(
        resourceMap,
        selectedService.value,
        dependencyMap
      );
      const { edges, externalNodes } = createFlowEdges(
        dependencyMap,
        resourceMap,
        selectedService.value
      );

      // External nodes are now handled in createFlowNodes, so we just need to add them to resourceMap
      externalNodes.forEach((externalNode, nodeId) => {
        resourceMap.set(nodeId, externalNode);
      });

      // Show both nodes and edges by default
      setNodes(nodes);
      setEdges(edges); // Show edges by default

      // Store the results for display
      setDependencies({
        nodes,
        edges: edges,
        resourceMap,
        dependencyMap,
        allExternalNodes: externalNodes,
      });
    }
  }, [
    dependencyResult,
    resources,
    parseMarkdownContent,
    selectedService.value,
    showLabels,
    createFlowNodes,
    createFlowEdges,
    setNodes,
    setEdges,
  ]);

  // Handle dependency analysis
  const handleDependencyAnalysis = useCallback(async () => {
    setShowCompletionAlert(false);
    const result = await startDependencyAnalysis({
      bedrockRegion: bedrockRegion.value,
    });

    if (!result.success && result.message) {
      // Handle error silently or show user-friendly message
    }
  }, [startDependencyAnalysis, bedrockRegion]);

  // Helper function to get resource type from service name (completely dynamic)
  const getResourceTypeFromService = (service) => {
    // Just return the service name as the type, no hardcoded mapping
    return service || "unknown";
  };

  // Simplified dependency detection - only use for fallback when AI doesn't provide connections
  const findResourceDependencies = (resourceInfo, resourceMap) => {
    const dependencies = [];
    const resource = resourceInfo.resource;

    // Helper function to add dependency
    const addDependency = (targetId, type) => {
      if (targetId && targetId !== resourceInfo.id) {
        dependencies.push({ target: targetId, type });
      }
    };

    // Only parse resource-based policy for dependencies (keep this as it's from the original data)
    if (resource.resource_based_policy) {
      const policy = resource.resource_based_policy;
      if (policy.Statement && Array.isArray(policy.Statement)) {
        policy.Statement.forEach((statement) => {
          // Extract principal services
          if (statement.Principal?.Service) {
            const services = Array.isArray(statement.Principal.Service)
              ? statement.Principal.Service
              : [statement.Principal.Service];

            services.forEach((service) => {
              addDependency(service, statement.Action || "policy-access");
            });
          }

          // Extract principal ARNs
          if (statement.Principal?.AWS) {
            const principals = Array.isArray(statement.Principal.AWS)
              ? statement.Principal.AWS
              : [statement.Principal.AWS];

            principals.forEach((principal) => {
              addDependency(principal, statement.Action || "policy-access");
            });
          }
        });
      }
    }

    // Remove duplicates
    const uniqueDependencies = dependencies.filter(
      (dep, index, self) =>
        index ===
        self.findIndex((d) => d.target === dep.target && d.type === dep.type)
    );

    return uniqueDependencies;
  };

  // Get resource label for display - show full actual resource ID
  const getResourceLabel = (resourceInfo) => {
    // Return the full actual resource ID as displayed in Resource Dependencies section
    return resourceInfo.id;
  };

  // Get node styling based on service name (completely dynamic)
  const getNodeStyle = (serviceName) => {
    // Generate consistent colors based on service name hash
    const getColorFromString = (str) => {
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        hash = str.charCodeAt(i) + ((hash << 5) - hash);
      }

      // Generate HSL color with good contrast
      const hue = Math.abs(hash) % 360;
      const saturation = 60 + (Math.abs(hash) % 30); // 60-90%
      const lightness = 85; // Light background
      const borderLightness = 45; // Darker border

      return {
        backgroundColor: `hsl(${hue}, ${saturation}%, ${lightness}%)`,
        border: `2px solid hsl(${hue}, ${saturation}%, ${borderLightness}%)`,
        color: `hsl(${hue}, ${saturation}%, ${borderLightness}%)`,
      };
    };

    const dynamicColors = getColorFromString(serviceName || "unknown");

    return {
      ...dynamicColors,
      borderRadius: "8px",
      padding: "10px",
      fontSize: "12px",
      fontWeight: "bold",
      textAlign: "center",
      minWidth: "120px",
      minHeight: "60px",
    };
  };

  // Get edge styling based on dependency type (completely dynamic)
  const getEdgeStyle = (depType, isExternal = false) => {
    // Generate consistent colors based on dependency type hash
    const getColorFromString = (str) => {
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        hash = str.charCodeAt(i) + ((hash << 5) - hash);
      }

      // Generate HSL color
      const hue = Math.abs(hash) % 360;
      const saturation = 70;
      const lightness = 50;

      return `hsl(${hue}, ${saturation}%, ${lightness}%)`;
    };

    const color = getColorFromString(depType || "default");
    const baseStyle = {
      stroke: color,
      strokeWidth: isExternal ? 1.5 : 2,
    };

    // Make external connections dashed
    if (isExternal) {
      return {
        ...baseStyle,
        strokeDasharray: "5,5",
        opacity: 0.7,
      };
    }

    return baseStyle;
  };

  // Helper function to extract service from target (completely dynamic)
  const getServiceFromTarget = (target) => {
    // Just return "external" for anything not in our resource map
    // Don't try to parse or extract - just display as is
    return "external";
  };

  // Helper function to get external node label - show full actual dependency name
  const getExternalNodeLabel = (externalNode) => {
    // Return the full actual dependency name as displayed in Resource Dependencies section
    return externalNode.id;
  };

  // Don't auto-analyze - only run on button click

  // Update visualization when service filter or display options change
  useEffect(() => {
    if (
      dependencies &&
      dependencies.resourceMap &&
      dependencies.dependencyMap &&
      !selectedResourceId // Only update when not showing individual resource graph
    ) {
      // Clear existing graph first to prevent ResizeObserver conflicts
      setNodes([]);
      setEdges([]);

      // Use requestAnimationFrame to ensure DOM is updated before setting new graph
      requestAnimationFrame(() => {
        const filteredNodes = createFlowNodes(
          dependencies.resourceMap,
          selectedService.value,
          dependencies.dependencyMap
        );
        const { edges: filteredEdges, externalNodes } = createFlowEdges(
          dependencies.dependencyMap,
          dependencies.resourceMap,
          selectedService.value
        );

        // Add external nodes to the filtered nodes with proper grid positioning
        const updatedNodes = [...filteredNodes];

        const spacing = { x: 400, y: 300 }; // Match the improved spacing from createFlowNodes
        // Continue grid from where internal nodes ended
        let currentCol = filteredNodes.length % 4; // Match the reduced columns (0-3)
        let currentRow = Math.floor(filteredNodes.length / 4); // Match the reduced columns

        externalNodes.forEach((externalNode, nodeId) => {
          // Only add if not already in the nodes
          if (!updatedNodes.find((node) => node.id === nodeId)) {
            updatedNodes.push({
              id: nodeId,
              type: "default",
              position: {
                x: currentCol * spacing.x,
                y: currentRow * spacing.y,
              },
              data: {
                label: showLabels
                  ? getExternalNodeLabel(externalNode)
                  : externalNode.subservice,
                resourceInfo: externalNode,
              },
              style: getNodeStyle("external"),
              className: `resource-node resource-external`,
            });

            // Update grid position for next external node
            currentCol++;
            if (currentCol > 3) {
              // Match the reduced columns (0-3)
              currentCol = 0;
              currentRow++;
            }
          }
        });

        // Preserve user-moved positions
        const nodesWithPreservedPositions = updatedNodes.map((node) => {
          const savedPosition = nodePositionsRef.current.get(node.id);
          if (savedPosition) {
            return { ...node, position: savedPosition };
          }
          return node;
        });

        // Create a set of all node IDs for edge validation
        const allNodeIds = new Set(
          nodesWithPreservedPositions.map((node) => node.id)
        );

        // Filter edges to only include those where source exists (target can be external)
        const validEdges = filteredEdges.filter((edge) =>
          allNodeIds.has(edge.source)
        );

        // Use another requestAnimationFrame to ensure smooth transition
        requestAnimationFrame(() => {
          setNodes(nodesWithPreservedPositions);
          setEdges(validEdges);
        });
      });
    }
  }, [
    selectedService.value,
    showLabels,
    edgeVisibilityMode,
    dependencies,
    selectedResourceId,
    createFlowNodes,
    createFlowEdges,
    setNodes,
    setEdges,
  ]);

  if (!hasScanned) {
    return (
      <Container>
        <Alert type="warning" header="Infrastructure Scan Required">{/* # nosemgrep: jsx-not-internationalized */}
          Please complete the infrastructure scan first before viewing resource
          dependencies. Go to the Resources Report page to scan your AWS
          infrastructure.
        </Alert>
      </Container>
    );
  }

  return (
    <SpaceBetween size="l">
      <Header
        variant="h1"
        description="AI-powered analysis of resource dependencies and relationships using Bedrock Claude 3.7 Sonnet to analyze resource-based policies and configurations"
        actions={
          <SpaceBetween direction="horizontal" size="xs">
            {selectedResourceId && (
              <Button
                onClick={clearSelection}
                iconName="close"
                disabled={isAnalyzingDependencies}
              >{/* # nosemgrep: jsx-not-internationalized */}
                Close Graph
              </Button>
            )}
            <Button
              onClick={handleDependencyAnalysis}
              loading={isAnalyzingDependencies}
              disabled={isAnalyzingDependencies || !bedrockRegion.value}
            >
              {isAnalyzingDependencies ? "Analyzing..." : "Get Dependencies"}
            </Button>
          </SpaceBetween>
        }
      >{/* # nosemgrep: jsx-not-internationalized */}
        Resource Dependencies
      </Header>

      {/* Prerequisites */}
      <Container>
        <Alert type="info" header="Prerequisites">
          <SpaceBetween size="s">
            <div>{/* # nosemgrep: jsx-not-internationalized */}
              <strong>{/* # nosemgrep: jsx-not-internationalized */}Amazon Bedrock Claude 3.7 Sonnet Model Required:</strong>
            </div>
            <ul style={{ marginLeft: "20px", marginBottom: "10px" }}>
              <li>{/* # nosemgrep: jsx-not-internationalized */}
                Ensure Amazon Bedrock Claude 3.7 Sonnet model is enabled in your selected
                region
              </li>
              <li>{/* # nosemgrep: jsx-not-internationalized */}
                Your AWS credentials must have access to Amazon Bedrock service
              </li>
              <li>{/* # nosemgrep: jsx-not-internationalized */}
                Claude 3.7 Sonnet model must be available and activated in the Bedrock
                console
              </li>
            </ul>
            <div>{/* # nosemgrep: jsx-not-internationalized */}
              <strong>{/* # nosemgrep: jsx-not-internationalized */}Supported Regions:</strong>  US East (N. Virginia), US East (Ohio), US West (Oregon), Europe (Frankfurt), Europe (Ireland), Europe (Paris)
            </div>
          </SpaceBetween>
        </Alert>
      </Container>

      {/* Controls */}
      <Container>
        <SpaceBetween size="m">
          <ColumnLayout columns={3} variant="text-grid">
            <FormField label="Filter by Service">
              <Select
                selectedOption={selectedService}
                onChange={({ detail }) => {
                  setSelectedService(detail.selectedOption);
                  // Clear selected resource when service filter changes to show main graph
                  if (selectedResourceId) {
                    clearSelection();
                  }
                }}
                options={serviceOptions}
                disabled={isAnalyzingDependencies}
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
                disabled={isAnalyzingDependencies}
                placeholder="Select a Bedrock region..."
              />
            </FormField>
            <FormField label="Display Options">
              <Toggle
                checked={showLabels}
                onChange={({ detail }) => setShowLabels(detail.checked)}
                disabled={isAnalyzingDependencies}
              >{/* # nosemgrep: jsx-not-internationalized */}
                Show Resource Labels
              </Toggle>
            </FormField>
          </ColumnLayout>
        </SpaceBetween>
      </Container>

      {/* Statistics */}
      {dependencies && (
        <Container>
          <Header variant="h2">{/* # nosemgrep: jsx-not-internationalized */}Dependency Statistics</Header>
          <ColumnLayout columns={4} variant="text-grid">
            <div>
              <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Total Resources</Box>
              <div>{dependencies.nodes.length}</div>
            </div>
            <div>
              <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Dependencies</Box>
              <div>{dependencies.edges.length}</div>
            </div>
            <div>
              <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Services</Box>
              <div>
                {
                  new Set(
                    dependencies.nodes.map((n) => n.data.resourceInfo.service)
                  ).size
                }
              </div>
            </div>
            <div>
              <Box variant="awsui-key-label">{/* # nosemgrep: jsx-not-internationalized */}Regions</Box>
              <div>
                {
                  new Set(
                    dependencies.nodes.map((n) => n.data.resourceInfo.region)
                  ).size
                }
              </div>
            </div>
          </ColumnLayout>
        </Container>
      )}

      {/* Completion Alert */}
      {showCompletionAlert && dependencies && (
        <Alert
          type="success"
          header="Dependency Analysis Complete!"
          dismissible
          onDismiss={() => setShowCompletionAlert(false)}
        >{/* # nosemgrep: jsx-not-internationalized */}
          Your AWS infrastructure dependency analysis has been completed
          successfully. The dependency graph is now available below.
        </Alert>
      )}

      {/* Error Display */}
      {dependencyError && (
        <Alert type="error" header="Dependency Analysis Failed">
          {dependencyError}
        </Alert>
      )}

      {/* Analysis Progress */}
      {isAnalyzingDependencies && (
        <Container>
          <Header variant="h2">{/* # nosemgrep: jsx-not-internationalized */}Dependency Analysis in Progress</Header>
          <SpaceBetween size="m">
            <Alert type="info" header="AI Dependency Analysis Running">{/* # nosemgrep: jsx-not-internationalized */}
              Your infrastructure dependencies are being analyzed using Amazon
              Bedrock. This process typically takes {estimatedTime}. Please keep
              this page open and do not navigate away.
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
              value={dependencyProgress}
              additionalInfo="Analyzing resource dependencies and relationships..."
              description="Progress is estimated based on typical analysis time"
            />
          </SpaceBetween>
        </Container>
      )}

      {/* Main Dependency Graph - Show when no specific resource is selected */}
      {dependencies && !selectedResourceId && nodes.length > 0 && (
        <Container data-testid="main-dependency-graph">
          <Header
            variant="h2"
            actions={
              <Button
                onClick={() => setIsFullscreen(true)}
                iconName="external"
                variant="normal"
              >{/* # nosemgrep: jsx-not-internationalized */}
                Fullscreen
              </Button>
            }
          >
            {selectedService.value === "all"
              ? "Infrastructure Dependency Graph - All Services"
              : `Infrastructure Dependency Graph - ${selectedService.label} Service`}
          </Header>
          <Alert type="info" header="Interactive Dependency Graph">{/* # nosemgrep: jsx-not-internationalized */}
            This graph shows the dependencies between your AWS resources. You
            can drag nodes to reposition them, zoom in/out, and pan around the
            graph. Click on any resource card below to focus on its specific
            dependencies.
          </Alert>
          <div style={{ height: "800px", border: "1px solid #ddd" }}>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={handleNodesChange} // Enable node movement with position preservation
              onEdgesChange={onEdgesChange} // Enable edge changes
              connectionLineType={ConnectionLineType.Step}
              defaultEdgeOptions={{
                type: "step",
                pathOptions: {
                  offset: 80, // Large offset to route around nodes
                  borderRadius: 20,
                },
                style: {
                  strokeWidth: 4, // Thicker edges for better visibility
                  stroke: "#666",
                  strokeOpacity: 0.9,
                },
                markerEnd: {
                  type: "arrowclosed",
                  width: 18,
                  height: 18,
                  color: "#666",
                },
              }}
              fitView
              fitViewOptions={{
                padding: 0.1,
                includeHiddenNodes: false,
                minZoom: 0.2,
                maxZoom: 2,
              }}
              attributionPosition="bottom-left"
              proOptions={{ hideAttribution: true }}
              nodesDraggable={true} // Enable node dragging
              nodesConnectable={false} // Keep connections disabled
              elementsSelectable={true} // Enable selection
              preventScrolling={false}
              zoomOnScroll={true}
              zoomOnPinch={true}
              panOnScroll={false}
              panOnScrollSpeed={0.5}
              zoomOnDoubleClick={true}
              nodeOrigin={[0.5, 0.5]}
              onError={(error) => {
                // Suppress ResizeObserver and other harmless errors
                if (
                  error.message &&
                  (error.message.includes("ResizeObserver") ||
                    error.message.includes("undelivered notifications"))
                ) {
                  return;
                }
                console.error("ReactFlow error:", error);
              }}
            >
              <Background />
              <Controls />
              <MiniMap
                nodeStrokeColor={(n) => {
                  if (n.style?.border) return n.style.border.split(" ")[2];
                  return "#eee";
                }}
                nodeColor={(n) => {
                  if (n.style?.backgroundColor) return n.style.backgroundColor;
                  return "#fff";
                }}
                nodeBorderRadius={2}
              />
            </ReactFlow>
          </div>
        </Container>
      )}

      {/* Dependency Graph - Only show when a resource is selected */}
      {selectedResourceId && dependencies && (
        <Container data-testid="dependency-graph">
          <Header
            variant="h2"
            actions={
              <Button
                onClick={() => setIsFullscreen(true)}
                iconName="external"
                variant="normal"
              >{/* # nosemgrep: jsx-not-internationalized */}
                Fullscreen
              </Button>
            }
          >{/* # nosemgrep: jsx-not-internationalized */}
            Dependency Graph for{" "}
            {selectedResourceId.split("/").pop() || selectedResourceId}
          </Header>
          <div style={{ height: "600px", border: "1px solid #ddd" }}>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={handleNodesChange} // Enable node movement with position preservation
              onEdgesChange={onEdgesChange} // Enable edge changes
              connectionLineType={ConnectionLineType.Step}
              defaultEdgeOptions={{
                type: "step",
                pathOptions: {
                  offset: 80, // Large offset to route around nodes
                  borderRadius: 20,
                },
                style: {
                  strokeWidth: 4, // Thicker edges for better visibility
                  stroke: "#666",
                  strokeOpacity: 0.9,
                },
                markerEnd: {
                  type: "arrowclosed",
                  width: 18,
                  height: 18,
                  color: "#666",
                },
              }}
              fitView
              fitViewOptions={{
                padding: 0.1,
                includeHiddenNodes: false,
                minZoom: 0.2,
                maxZoom: 2,
              }}
              attributionPosition="bottom-left"
              proOptions={{ hideAttribution: true }}
              nodesDraggable={true} // Enable node dragging
              nodesConnectable={false} // Keep connections disabled
              elementsSelectable={true} // Enable selection
              preventScrolling={false}
              zoomOnScroll={true}
              zoomOnPinch={true}
              panOnScroll={false}
              panOnScrollSpeed={0.5}
              zoomOnDoubleClick={true}
              nodeOrigin={[0.5, 0.5]}
              onError={(error) => {
                // Suppress ResizeObserver and other harmless errors
                if (
                  error.message &&
                  (error.message.includes("ResizeObserver") ||
                    error.message.includes("undelivered notifications"))
                ) {
                  return;
                }
                console.error("ReactFlow error:", error);
              }}
            >
              <Background />
              <Controls />
              <MiniMap
                nodeStrokeColor={(n) => {
                  if (n.style?.border) return n.style.border.split(" ")[2];
                  return "#eee";
                }}
                nodeColor={(n) => {
                  if (n.style?.backgroundColor) return n.style.backgroundColor;
                  return "#fff";
                }}
                nodeBorderRadius={2}
              />
            </ReactFlow>
          </div>
        </Container>
      )}

      {/* Resource Details - Show individual resource dependencies */}
      {dependencies && dependencies.nodes.length > 0 && (
        <Container>
          <Header variant="h2">{/* # nosemgrep: jsx-not-internationalized */}Resource Details</Header>
          <Cards
            cardDefinition={{
              header: (item) => (
                <SpaceBetween direction="horizontal" size="xs">
                  <Badge
                    color={getResourceBadgeColor(item.data.resourceInfo.type)}
                  >
                    {item.data.resourceInfo.type}
                  </Badge>
                  <Box variant="h4">{item.data.resourceInfo.subservice}</Box>
                </SpaceBetween>
              ),
              sections: [
                {
                  id: "id",
                  header: "Resource ID",
                  content: (item) => item.id,
                },
                {
                  id: "service",
                  header: "Service",
                  content: (item) =>
                    `${item.data.resourceInfo.service} (${item.data.resourceInfo.region})`,
                },
                {
                  id: "dependencies",
                  header: "Dependencies",
                  content: (item) => {
                    const resourceDeps =
                      dependencies.dependencyMap.get(item.id) || [];
                    if (resourceDeps.length === 0) {
                      return (
                        <Box color="text-body-secondary">{/* # nosemgrep: jsx-not-internationalized */}
                          No dependencies found
                        </Box>
                      );
                    }
                    return (
                      <SpaceBetween size="xs">
                        <Button
                          size="small"
                          onClick={() => handleResourceSelection(item.id)}
                          iconName="share"
                        >{/* # nosemgrep: jsx-not-internationalized */}
                          View Dependency Graph ({resourceDeps.length})
                        </Button>
                        {resourceDeps.map((dep, index) => (
                          <Box key={index} variant="small">
                            <strong>{dep.type}:</strong> {dep.target}
                          </Box>
                        ))}
                      </SpaceBetween>
                    );
                  },
                },
              ],
            }}
            cardsPerRow={[
              { cards: 1 },
              { minWidth: 500, cards: 2 },
              { minWidth: 800, cards: 3 },
            ]}
            items={dependencies.nodes.filter((node) => {
              if (selectedService.value === "all") return true;
              return node.data.resourceInfo.service === selectedService.value;
            })}
            loadingText="Loading resources"
            empty={
              <Box textAlign="center" color="inherit">
                <b>{/* # nosemgrep: jsx-not-internationalized */}No resources</b>
                <Box variant="p" color="inherit">{/* # nosemgrep: jsx-not-internationalized */}
                  No resources found for the selected service.
                </Box>
              </Box>
            }
          />
        </Container>
      )}

      {/* Fullscreen Modal for Dependency Graph */}
      <Modal
        visible={isFullscreen}
        onDismiss={() => setIsFullscreen(false)}
        size="max"
        header="Infrastructure Dependency Graph"
      >
        <div style={{ height: "80vh", width: "100%" }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={handleNodesChange}
            onEdgesChange={onEdgesChange}
            connectionLineType={ConnectionLineType.Step}
            defaultEdgeOptions={{
              type: "step",
              pathOptions: {
                offset: 80,
                borderRadius: 20,
              },
              style: {
                strokeWidth: 4,
                stroke: "#666",
                strokeOpacity: 0.9,
              },
              markerEnd: {
                type: "arrowclosed",
                width: 18,
                height: 18,
                color: "#666",
              },
            }}
            fitView
            fitViewOptions={{
              padding: 0.1,
              includeHiddenNodes: false,
              minZoom: 0.1,
              maxZoom: 3,
            }}
            attributionPosition="bottom-left"
            proOptions={{ hideAttribution: true }}
            nodesDraggable={true}
            nodesConnectable={false}
            elementsSelectable={true}
            preventScrolling={false}
            zoomOnScroll={true}
            zoomOnPinch={true}
            panOnScroll={false}
            panOnScrollSpeed={0.5}
            zoomOnDoubleClick={true}
            nodeOrigin={[0.5, 0.5]}
          >
            <Background />
            <Controls />
            <MiniMap
              nodeStrokeColor={(n) => {
                if (n.style?.border) return n.style.border.split(" ")[2];
                return "#eee";
              }}
              nodeColor={(n) => {
                if (n.style?.backgroundColor) return n.style.backgroundColor;
                return "#fff";
              }}
              nodeBorderRadius={2}
            />
          </ReactFlow>
        </div>
      </Modal>
    </SpaceBetween>
  );
};

// Helper function to get badge color based on resource type
const getResourceBadgeColor = (resourceType) => {
  const colorMap = {
    network: "blue",
    compute: "purple",
    storage: "green",
    database: "orange",
    security: "red",
    other: "grey",
  };
  return colorMap[resourceType] || "grey";
};

export default ResourceDependencies;