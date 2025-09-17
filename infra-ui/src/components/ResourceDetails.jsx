// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import {
  Table
} from '@cloudscape-design/components';

const ResourceDetails = ({ resource }) => {
  // Convert resource object to array of key-value pairs for display
  const resourceItems = Object.entries(resource).map(([key, value]) => {
    // Format the value based on its type
    let formattedValue;
    
    if (value === null) {
      formattedValue = "null";
    } else if (typeof value === 'object') {
      formattedValue = JSON.stringify(value, null, 2);
    } else {
      formattedValue = String(value);
    }

    return { key, value: formattedValue };
  });

  return (
      <Table
        columnDefinitions={[
          {
            id: 'key',
            header: 'Property',
            cell: item => item.key,
            width: 200
          },
          {
            id: 'value',
            header: 'Value',
            cell: item => {
              if (typeof item.value === 'string' && (item.value.startsWith('{') || item.value.startsWith('['))) {
                return (
                  <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>
                    {item.value}
                  </pre>
                );
              }
              return item.value;
            }
          }
        ]}
        items={resourceItems}
        variant="embedded"
        stripedRows
        stickyHeader
      />
  );
};

export default ResourceDetails;