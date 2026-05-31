# SentinelX Mini DSL

The DSL is intentionally compact and reads like a small security command line.

## Grammar

```text
statement   := show_cmd | help_cmd | explain_cmd
show_cmd    := SHOW (THREATS | TRAFFIC | STATS | LATEST) query_opts
help_cmd    := HELP
explain_cmd := EXPLAIN <free-form query>

query_opts  := (LIMIT n)? (TOP n)? (WHERE filter (AND filter)*)? (ORDER BY field (ASC | DESC)?)?
filter      := field op value
op          := = | != | > | < | >= | <=
```

## Commands

- `SHOW THREATS LIMIT 10`
  - Lists attack rows from the database when available.
- `SHOW THREATS WHERE severity = HIGH`
  - Filters by threat fields.
- `SHOW TRAFFIC LIMIT 5`
  - Shows recent traffic snapshots.
- `SHOW STATS`
  - Shows the current live summary.
- `SHOW LATEST`
  - Returns the latest prediction.
- `HELP`
  - Shows a short command reference.

## Data Source Order

1. Database read from `predictions` and `traffic_stats`.
2. FastAPI fallback at `SENTINELX_API_BASE` or `http://127.0.0.1:8000`.
3. If both fail, the query raises an error.
