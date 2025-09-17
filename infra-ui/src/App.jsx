// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { useState } from "react";
import { ResourceProvider } from "./context/ResourceContext";
import DashboardView from "./components/DashboardView";
import InfrastructureAnalysis from "./components/InfrastructureAnalysis";
import ResourceDependencies from "./components/ResourceDependencies";
import {
  AppLayout,
  SideNavigation,
  TopNavigation,
} from "@cloudscape-design/components";
import "@cloudscape-design/global-styles/index.css";

const AppContent = () => {
  const [activeHref, setActiveHref] = useState("#resources-report");

  const navigationItems = [
    {
      type: "link",
      text: "Resources Report",
      href: "#resources-report",
    },
    {
      type: "link",
      text: "AI Analysis",
      href: "#ai-analysis",
    },
    {
      type: "link",
      text: "Dependencies",
      href: "#dependencies",
    },
  ];

  const renderContent = () => {
    switch (activeHref) {
      case "#ai-analysis":
        return <InfrastructureAnalysis />;
      case "#dependencies":
        return <ResourceDependencies />;
      case "#resources-report":
      default:
        return <DashboardView />;
    }
  };

  return (
    <>
      <TopNavigation
        identity={{
          title: "AWS Infrastructure Report Generator",
        }}
      />
      <AppLayout
        content={renderContent()}
        navigation={
          <SideNavigation
            activeHref={activeHref}
            onFollow={(event) => {
              if (!event.detail.external) {
                event.preventDefault();
                setActiveHref(event.detail.href);
              }
            }}
            items={navigationItems}
          />
        }
        toolsHide
      />
    </>
  );
};

function App() {
  return (
    <ResourceProvider>
      <AppContent />
    </ResourceProvider>
  );
}

export default App;
