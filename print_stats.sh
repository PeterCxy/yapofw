#!/usr/bin/env bash
# Convert numbers in yapofw's stats files to human-readable forms
STATS_FILE="$1"

if [ -z "$STATS_FILE" ]; then
    echo "Usage: print_stats.sh <stats_file>"
    exit 1
fi

if [ ! -f "$STATS_FILE" ]; then
    echo "$STATS_FILE does not exist"
    exit 1
fi

while IFS= read line; do
    for segment in $line; do
        if [ ! -z "${segment##*[!0-9]*}" ]; then
            # Make numbers human-readable
            echo -n "$(numfmt --to=iec-i --suffix=B $segment) "
        else
            echo -n "$segment "
        fi
    done
    echo ""
done < "$STATS_FILE"