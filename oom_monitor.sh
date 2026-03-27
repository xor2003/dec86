#!/bin/bash

# Get free memory in MB
FREE_MEM=$(free -m | awk 'NR==2{print $4}')

# Get total memory in MB
TOTAL_MEM=$(free -m | awk 'NR==2{print $2}')

# Threshold: 95% of free memory
THRESHOLD=$((FREE_MEM * 95 / 100))

# Find the process with highest memory usage
TOP_PROCESS=$(ps -eo pid,pmem,rss,comm --no-headers | sort -k3 -nr | head -1)

# Extract PID, %MEM, RSS (in KB), COMMAND
PID=$(echo $TOP_PROCESS | awk '{print $1}')
PERCENT=$(echo $TOP_PROCESS | awk '{print $2}')
RSS_KB=$(echo $TOP_PROCESS | awk '{print $3}')
COMMAND=$(echo $TOP_PROCESS | awk '{print $4}')

# Convert RSS to MB
RSS_MB=$((RSS_KB / 1024))

# Check if RSS > threshold
if [ $RSS_MB -gt $THRESHOLD ]; then
    echo "Killing process $PID ($COMMAND) using ${RSS_MB}MB, which is more than 95% of free memory (${THRESHOLD}MB)"
    kill -9 $PID
else
    echo "No process using more than 95% of free memory. Top process: $COMMAND using ${RSS_MB}MB"
fi