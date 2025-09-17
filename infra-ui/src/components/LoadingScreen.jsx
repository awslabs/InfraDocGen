// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { useState, useEffect } from 'react';
import {
  Box,
  Spinner
} from '@cloudscape-design/components';

const LoadingScreen = () => {
  const [messageIndex, setMessageIndex] = useState(0);
  
  const messages = [
  "Scanning resources...",
  "Loading services...",
  "Discovering assets...",
  "Fetching data...",
  "Processing results...",
  "Organizing information...",
  "Analyzing configurations...",
  "Building report...",
  "Almost there..."
  ];

  useEffect(() => {
    const interval = setInterval(() => {
      setMessageIndex(prev => (prev + 1) % messages.length);
    }, 10000);

    return () => clearInterval(interval);
  }, [messages.length]);

  return (
    <Box textAlign="center" padding={{ top: 'xxxl' }}>
      <Spinner size="large" />
      <Box variant="p" padding={{ top: 's' }}>
        {messages[messageIndex]}
      </Box>
    </Box>
  );
};

export default LoadingScreen;