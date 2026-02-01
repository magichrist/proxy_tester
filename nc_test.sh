#!/bin/bash

# Usage:
# ./nc_test.sh input.txt output.txt

INPUT="$1"
OUTPUT="$2"
NC_BIN="nc"

if [[ -z "$INPUT" || -z "$OUTPUT" ]]; then
  echo "Usage: $0 <input_file> <output_file>"
  exit 1
fi

# Read config from Config.py
TIMEOUT=$(python3 - <<'EOF'
import Config
print(Config.NC_TIMEOUT)
EOF
)

MAX_JOBS=$(python3 - <<'EOF'
import Config
print(Config.NC_JOBS)
EOF
)


> "$OUTPUT"
jobs=0

while IFS= read -r link; do
  (
    host=$(echo "$link" | sed -E 's|^[a-zA-Z0-9+.-]+://[^@]+@([^:/?#]+).*|\1|')
    port=$(echo "$link" | sed -nE 's|^[a-zA-Z0-9+.-]+://[^@]+@[^:/?#]+:([0-9]+).*|\1|p')

    if [[ -n "$host" && -n "$port" ]]; then
      if "$NC_BIN" -z -G "$TIMEOUT" "$host" "$port" >/dev/null 2>&1; then
        echo "✔ alive  $host:$port"
        echo "$link" >> "$OUTPUT"
      else
        echo "✖ dead   $host:$port"
      fi
    fi
  ) &

  ((jobs++))

  while (( jobs >= MAX_JOBS )); do
    sleep 0.1
    jobs=$(jobs -p | wc -l | tr -d ' ')
  done

done < "$INPUT"

wait
