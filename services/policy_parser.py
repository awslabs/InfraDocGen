# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

def extract_actions_and_resources_from_policy(policy_doc):
    actions = set()
    resources = set()
    statements = policy_doc.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        stmt_actions = stmt.get("Action", [])
        stmt_resources = stmt.get("Resource", [])

        if isinstance(stmt_actions, str):
            stmt_actions = [stmt_actions]
        if isinstance(stmt_resources, str):
            stmt_resources = [stmt_resources]

        actions.update(stmt_actions)
        resources.update(stmt_resources)

    return list(actions), list(resources)
