# Collector package
from collector.lab_simulator import (
    generate_normal_baseline_events,
    generate_macro_attack_scenario,
    generate_drift_workload
)
from collector.live_sysmon import is_sysmon_active, collect_live_sysmon_events
from collector.live_processes import capture_live_host_processes
