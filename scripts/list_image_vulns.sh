#!/bin/bash

# --- CONFIGURATION ---
CENTRAL_URL="https://central-stackrox.apps.cluster-drkdl.drkdl.sandbox2071.opentlc.com" # Replace with your Central URL
API_TOKEN="<API_TOKEN>" # Replace with your TOKEN

FIELDS=$(cat <<EOF
    createdAt
    cve
    cvss
    discoveredAtImage
    envImpact
    isFixable
    fixedByVersion
    id
    impactScore
    lastModified
    lastScanned
    link
    operatingSystem
    publishedOn
    scoreVersion
    severity
    summary
    suppressActivation
    suppressExpiry
    suppressed
    fixedByVersion
    vulnerabilityState
    imageComponentCount
    imageCount
    deploymentCount
    images {
      id
      name {
        tag
        remote
        registry
        fullName
      }
      operatingSystem
      scanTime
      priority
      deployments {
        id
        name
        namespace
        platformComponent
        cluster {
          id
          name
        }
      }
    }
    __typename
EOF
)

# Compact to a single line
FIELDS=$(echo "$FIELDS" | tr '\n' ' ')

QUERY=$(cat <<EOF
{
  "operationName": "getImageVulnerabilities",
  "variables": {
    "query": "Platform Component:false",
    "pagination": {
      "limit": 200,
      "offset": 0,
      "sortOptions": [
        {
          "field": "CVE",
          "reversed": false
        }
      ]
    }
  },
  "query": "query getImageVulnerabilities(\$query: String, \$pagination: Pagination) { imageVulnerabilities(query: \$query, pagination: \$pagination) { ${FIELDS} __typename } }"
}
EOF
)

curl -s -k "${CENTRAL_URL}/api/graphql" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  --data-raw "$QUERY"