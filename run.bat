@echo off
cd /d "%~dp0"
python gatekeeper_validate.py --rest-url https://portal.castsoftware.com/VINCIENERGIES_CODEX_HDED/rest --domain AED --user codex --password Vinci_Energie$123 --app CODEX --rule-ids auto --limit 50000000 --no-true-positives --out report.csv


rem python gatekeeper_validate.py --url http://imaging:8283/mcp/gatekeeper --api-key $IMAGING_KEY --app MyApp --source-root .\src_test --rule-ids auto --limit 50 --out report.csv

