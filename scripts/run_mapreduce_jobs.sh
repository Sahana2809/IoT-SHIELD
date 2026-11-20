#!/bin/bash
# Module 5: run every IoT-23 MapReduce job against /iot23/processed,
# capturing wall-clock time and job counters for the performance report.
set -uo pipefail

export HADOOP_HOME=/opt/hadoop
PROJECT_DIR="/Users/sahanaagadi/Downloads/eda notes/resumes/7th sem/bda/project"
JAR="$PROJECT_DIR/mapreduce/iot23-analysis.jar"
INPUT="/iot23/processed"
OUTPUT_ROOT="/iot23/output"
LOG_DIR="$PROJECT_DIR/logs"
mkdir -p "$LOG_DIR"

NAMES="traffic_classification attack_category protocol ports volume ips scenario_comparison"
CLASS_traffic_classification="iot23.TrafficClassification"
CLASS_attack_category="iot23.AttackCategoryDistribution"
CLASS_protocol="iot23.ProtocolDistribution"
CLASS_ports="iot23.PortAnalysis"
CLASS_volume="iot23.TrafficVolume"
CLASS_ips="iot23.IpAnalysis"
CLASS_scenario_comparison="iot23.ScenarioComparison"

hdfs dfs -rm -r -f "$OUTPUT_ROOT" > /dev/null 2>&1

SUMMARY="$PROJECT_DIR/docs/module5_performance.md"
echo "# Module 5 — Execution and Performance" > "$SUMMARY"
echo "" >> "$SUMMARY"
echo "| Job | Wall time (s) | Map input records | Map output records | Reduce output records |" >> "$SUMMARY"
echo "|---|---|---|---|---|" >> "$SUMMARY"

for name in $NAMES; do
  class_var="CLASS_$name"
  class="${!class_var}"
  out="$OUTPUT_ROOT/$name"
  log="$LOG_DIR/$name.log"
  echo "=== Running $name ($class) ==="
  start=$(date +%s)
  hadoop jar "$JAR" "$class" "$INPUT" "$out" > "$log" 2>&1
  status=$?
  end=$(date +%s)
  elapsed=$((end - start))
  echo "    exit=$status elapsed=${elapsed}s  log=$log"

  map_in=$(grep "Map input records" "$log" | tail -1 | grep -oE '[0-9]+$')
  map_out=$(grep "Map output records" "$log" | tail -1 | grep -oE '[0-9]+$')
  red_out=$(grep "Reduce output records" "$log" | tail -1 | grep -oE '[0-9]+$')
  echo "| $name | $elapsed | ${map_in:-NA} | ${map_out:-NA} | ${red_out:-NA} |" >> "$SUMMARY"
done

echo "" >> "$SUMMARY"
echo "Summary written to $SUMMARY"
