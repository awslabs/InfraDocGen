// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import {
  ContentLayout,
  SpaceBetween,
} from '@cloudscape-design/components';
import { useResources } from '../context/ResourceContext';
import PrerequisitesBox from './PrerequisitesBox';
import ResourcesReport from './ResourcesReport';
import LoadingScreen from './LoadingScreen';

const DashboardView = () => {
  const { scanResources, loading } = useResources();

  const handleScanClick = () => {
    // Call scan with empty parameters - will use system AWS credentials
    scanResources({});
  };

  return (
    <ContentLayout>
      <SpaceBetween size="l">
        <PrerequisitesBox onScanClick={handleScanClick} loading={loading} />
        
        {loading ? (
          <LoadingScreen />
        ) : (
          <ResourcesReport />
        )}
      </SpaceBetween>
    </ContentLayout>
  );
};

export default DashboardView;