#!/usr/bin/env bash
# Generate opencode.json from template + environment variables.
#
# Reads OPENCODE_SMALL_MODEL, OPENCODE_MEDIUM_MODEL, OPENCODE_LARGE_MODEL
# env vars to build the models block, then substitutes ${VAR} placeholders
# with actual values from the environment.
#
# Usage:  config_opencode.sh [template] [output]
#   template  defaults to /app/configs/opencode.template.json
#   output    defaults to $XDG_CONFIG_HOME/opencode/opencode.json
set -e

TEMPLATE_FILE="${1:-/app/configs/opencode.template.json}"
OUTPUT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"
OUTPUT_FILE="${2:-$OUTPUT_DIR/opencode.json}"

# -------------------------
# Defaults
# -------------------------
: "${OPENCODE_SMALL_MODEL:=qwen3.6}"
: "${OPENCODE_MEDIUM_MODEL:=qwen3.6}"
: "${OPENCODE_LARGE_MODEL:=qwen3.6}"

if [ ! -f "$TEMPLATE_FILE" ]; then
  echo "ERROR: template not found: $TEMPLATE_FILE" >&2
  exit 1
fi

# -------------------------
# Collect unique model aliases from the tier env vars
# -------------------------
MODELS_RAW=$(printf '%s\n' \
  "$OPENCODE_SMALL_MODEL" \
  "$OPENCODE_MEDIUM_MODEL" \
  "$OPENCODE_LARGE_MODEL" \
  | sort | uniq)

# -------------------------
# Build the models JSON block
# -------------------------
NL=$'\n'
IND="      "

MODELS_JSON="{"
FIRST=1
for model in $MODELS_RAW; do
  pretty=$(echo "$model" \
    | sed 's/-/ /g; s/\./ /g' \
    | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)}1')

  if [ $FIRST -eq 1 ]; then
    FIRST=0
  else
    MODELS_JSON+=","
  fi

  MODELS_JSON+="${NL}${IND}  \"$model\": {${NL}${IND}    \"name\": \"$pretty\"${NL}${IND}  }"
done
MODELS_JSON+="${NL}${IND}}"

# -------------------------
# Generate output
# -------------------------
mkdir -p "$OUTPUT_DIR"
cp "$TEMPLATE_FILE" "$OUTPUT_FILE"

# Replace __MODELS__ placeholder
perl -0777 -i -pe "s|__MODELS__|$MODELS_JSON|g" "$OUTPUT_FILE"

# Replace ${VAR} references with environment values
for var in LITELLM_BASE_URL LITELLM_API_KEY \
           OPENCODE_SMALL_MODEL OPENCODE_MEDIUM_MODEL OPENCODE_LARGE_MODEL; do
  value="${!var}"
  if [ -n "$value" ]; then
    value_escaped=$(printf '%s' "$value" | sed 's/[\/&]/\\&/g')
    sed -i "s|\${$var}|$value_escaped|g" "$OUTPUT_FILE" 2>/dev/null || \
    sed -i '' "s|\${$var}|$value_escaped|g" "$OUTPUT_FILE"
  fi
done

echo "OpenCode config generated: $OUTPUT_FILE"
