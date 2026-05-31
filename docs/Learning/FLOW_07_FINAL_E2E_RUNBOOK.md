# Flow 07 - Final End-to-End Runbook

## Final Goal
Single dashboard flow:
- sniff live traffic
- run ML predictions
- persist in DB
- query by DSL in UI

## Steps
1. Install dependencies
```bash
python -m pip install -r requirements.txt
```

2. Start Streamlit dashboard
```bash
streamlit run Frontend/app.py
```

3. Verify backend in dashboard
- API should show ONLINE in pipeline status.
- DB should show ONLINE.
- Prediction/stat row counts should grow over time.

4. Verify CLI DSL against DB
```bash
python Backend/compiler/cli.py "show predictions limit 20"
python Backend/compiler/cli.py "show latest"
python Backend/compiler/cli.py "show threats limit 10"
```

## Expected Behavior
- `show predictions` should return multiple rows while capture is active.
- `show threats` may be empty if traffic is mostly normal.
- `show latest` should show last prediction row from DB.
