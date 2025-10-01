#!/bin/bash

# --- CONFIGURATION ---
CENTRAL_URL="https://central-stackrox.apps.cluster-drkdl.drkdl.sandbox2071.opentlc.com" # Replace with your Central URL
API_TOKEN="<API_TOKEN>" # Replace with your TOKEN

FIELDS=$(cat <<EOF
    cve
    severity
    isFixable
    cvss
    scoreVersion
    envImpact
    impactScore
    createdAt
    lastModified
    lastScanned
    summary
    link
    publishedOn
    fixedByVersion
    vulnerabilityType
    clusterCount
    clusters {
        id
        name
        type
    }
EOF
)

# Compact into a single line
FIELDS=$(echo "$FIELDS" | tr '\n' ' ')

QUERY=$(cat <<EOF
{
  "operationName": "getClusterVulnerabilities",
  "variables": {
    "query": ""
  },
  "query": "query getClusterVulnerabilities(\$query: String) { clusterVulnerabilities(query: \$query) { ${FIELDS} __typename } }"
}
EOF
)

curl -s -k "${CENTRAL_URL}/api/graphql" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  --data-raw "$QUERY"