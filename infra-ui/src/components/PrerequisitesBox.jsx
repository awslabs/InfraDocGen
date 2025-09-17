// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import {
  Box,
  Container,
  SpaceBetween,
  Button,
} from '@cloudscape-design/components';
import Icon from "@cloudscape-design/components/icon";
import "../style/style.css";

const PrerequisitesBox = ({ onScanClick, loading }) => {
  return (
    <Container>
      <Box padding="m">
        <SpaceBetween size="m">
          <div>
            <h2 style={{ margin: '0', fontSize: '16px', fontWeight: 'bold' }}><Icon name="status-info" variant="link" />{/* # nosemgrep: jsx-not-internationalized */} Prerequisites</h2>
            <p style={{ margin: '8px 0' }}>{/* # nosemgrep: jsx-not-internationalized */}
            Before scanning AWS resources, ensure you have configured your AWS credentials by running:
            </p>
            <div className="code-block">{/* # nosemgrep: jsx-not-internationalized */}
              <code>{/* # nosemgrep: jsx-not-internationalized */}$ aws configure</code>
            </div>
          </div>
          
          <div style={{ textAlign: 'right' }}>
            <Button
              variant="primary"
              loading={loading}
              iconName="search"
              onClick={onScanClick}
            >{/* # nosemgrep: jsx-not-internationalized */}
              Start Scanning
            </Button>
          </div>
        </SpaceBetween>
      </Box>
    </Container>
  );
};

export default PrerequisitesBox;