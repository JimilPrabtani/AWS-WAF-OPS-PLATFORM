# Detection as code

Each YAML file here is one detection with its reasoning attached. The file is
the source of truth: the Logs Insights query, the threshold, why that threshold
and not another, what produces false positives, and what to do when it fires.

The point is the `tuning_notes` and `false_positives` fields. A query with a
hardcoded `> 100` and no explanation is indistinguishable from a guess. A
threshold derived from measured benign traffic, with its blind spots written
down, is detection engineering.

Two of these ship with `TODO - measure` in the tuning notes, deliberately. They
stay that way until dev has run long enough to produce real numbers. Writing a
confident threshold you cannot defend is worse than admitting you have not
measured yet.

## Adding one

1. Write the query and confirm it returns what you expect in Logs Insights.
2. Run the benign traffic suite and record what the query does on clean traffic.
3. Set the threshold above the observed benign maximum, with headroom.
4. Write down what you measured, in `tuning_notes`.
5. Add a `metric_filter_pattern` if it should raise an alarm rather than only
   being queried after an incident.
6. Reference it in `envs/*/main.tf` under `detections`.

## Why metric filters and not just queries

Logs Insights queries are for investigation -- you run them when you already
suspect something. A metric filter turns matching records into a CloudWatch
metric, which an alarm can watch continuously. Detections worth alerting on need
both: the filter to notice, the query to investigate.
