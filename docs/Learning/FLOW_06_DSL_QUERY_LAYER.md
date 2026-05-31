# Flow 06 - DSL Query Layer

## Objective
Query security data through a mini domain-specific language.

## Primary Files
- `Backend/compiler/lexer.py`
- `Backend/compiler/parser.py`
- `Backend/compiler/engine.py`
- `Backend/compiler/datasource.py`
- `Backend/compiler/cli.py`

## Key Commands
- `show predictions limit 20`
- `show threats limit 10`
- `show traffic limit 5`
- `show stats`
- `show latest`

## Data Source Strategy
- DB first
- API fallback
- Local empty response if nothing available

## Run
```bash
python Backend/compiler/cli.py "show predictions limit 20"
```
