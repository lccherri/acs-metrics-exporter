#!/usr/bin/env bash

CENTRAL_URL="https://central-stackrox.apps.cluster-drkdl.drkdl.sandbox2071.opentlc.com" # Replace with your Central URL
API_TOKEN="<API_TOKEN>" # Replace with your TOKEN

# Definition of the GraphQL query to fetch clusters and some useful fields.
GRAPHQL_QUERY=$(cat <<EOF
query getClusters {
  clusters {
    id
    name
    type
  }
}
EOF
)

# Compact to a single line
GRAPHQL_QUERY=$(echo "$GRAPHQL_QUERY" | tr '\n' ' ')

# Build the JSON payload to be sent in the POST request body
JSON_PAYLOAD=$(cat <<EOF
{
  "operationName": "getClusters",
  "query": "$GRAPHQL_QUERY"
}
EOF
)

# Executes the curl call and stores the response
# -s : silent mode (no progress bar)
# -k : ignores certificate verification (useful for test environments)
curl -k -X POST \
  -H "Authorization: Bearer ${API_TOKEN}" \
  -H "Content-Type: application/json" \
  "${CENTRAL_URL}/api/graphql" \
  --data-raw "$JSON_PAYLOAD"