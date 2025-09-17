# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from services.policy_parser import extract_actions_and_resources_from_policy
from services.policy_resolver import (
    get_all_iam_entities,
    get_policies_for_user,
    get_policies_for_role,
    get_policies_for_group,
    get_resource_based_policy
)

def build_dependency_graph(session, discovered_resources):
    iam = session.client('iam')
    users, roles, groups = get_all_iam_entities(session)

    graph = {}

    # Map IAM principals to accessible resources
    for user in users:
        uname = user['UserName']
        attached, inline = get_policies_for_user(iam, uname)
        principal = f"user:{uname}"
        graph[principal] = []

        for policy_doc in inline:
            actions, resources = extract_actions_and_resources_from_policy(policy_doc)
            for r in resources:
                graph[principal].append({"resource": r, "actions": actions})

    for role in roles:
        rname = role['RoleName']
        attached, inline = get_policies_for_role(iam, rname)
        principal = f"role:{rname}"
        graph[principal] = []

        for policy_doc in inline:
            actions, resources = extract_actions_and_resources_from_policy(policy_doc)
            for r in resources:
                graph[principal].append({"resource": r, "actions": actions})

    for group in groups:
        gname = group['GroupName']
        attached, inline = get_policies_for_group(iam, gname)
        principal = f"group:{gname}"
        graph[principal] = []

        for policy_doc in inline:
            actions, resources = extract_actions_and_resources_from_policy(policy_doc)
            for r in resources:
                graph[principal].append({"resource": r, "actions": actions})

    # Enhance discovered resources with reverse links
    resource_map = {}
    for res in discovered_resources:
        service = res.get("service")
        region = res.get("region")
        client = session.client(service, region_name=region)
        for item in res.get("resources", []):
            if isinstance(item, dict):
                arn = item.get("Arn")
                if arn:
                    accessed_by = []
                    for principal, accesses in graph.items():
                        for access in accesses:
                            if access["resource"] == arn:
                                accessed_by.append({
                                    "principal": principal,
                                    "actions": access["actions"]
                                })
                    item["accessed_by"] = accessed_by
                    # Resource-based policy
                    name = item.get("Name")
                    if name:
                        policy_json = get_resource_based_policy(client, service, name)
                        item["resource_policy"] = policy_json

    return {item.get("Arn"): item for res in discovered_resources for item in res.get("resources", []) if isinstance(item, dict) and "Arn" in item}

