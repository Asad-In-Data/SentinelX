# Flow 05 - Database Layer

## Objective
Store predictions and traffic stats for persistent querying.

## Primary Files
- `Backend/db/models.py`
- `Backend/db/database.py`
- `Backend/db/cli.py`
- Alembic configs and versions

## Tables
- `predictions`
- `traffic_stats`

## What It Does
- `TrafficAnalyzer` enqueues prediction/stat snapshots.
- Background DB worker saves rows asynchronously.
- DSL and admin tools query this persisted data.

## Quick Check
```bash
python Backend/db/cli.py list-predictions --limit 10
python Backend/db/cli.py show-stats --limit 10
```
