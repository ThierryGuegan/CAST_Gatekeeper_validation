@echo off
cd /d "%~dp0"

python gatekeeper_validate.py --list-rules

rem python gatekeeper_validate.py --rest-url https://portal.castsoftware.com/VINCIENERGIES_CODEX_HDED/rest --domain AED --user codex --password Vinci_Energie$123 --app CODEX --rule-ids auto --limit 2000 --no-true-positives --out report.csv
rem python gatekeeper_validate.py --rest-url https://portal.castsoftware.com/VINCIENERGIES_CODEX_HDED/rest --domain AED --user codex --password Vinci_Energie$123 --app CODEX --rule-ids abap --per-rule-limit 200 --no-true-positives --out report.csv
rem python gatekeeper_validate.py --rest-url https://portal.castsoftware.com/VINCIENERGIES_CODEX_HDED/rest --domain AED --user codex --password Vinci_Energie$123 --app CODEX --rule-ids all --per-rule-limit 200 --no-true-positives --out report.csv
rem python gatekeeper_validate.py --rest-url https://portal.castsoftware.com/VINCIENERGIES_CODEX_HDED/rest --domain AED --user codex --password Vinci_Energie$123 --app CODEX --rule-ids auto --per-rule-limit 200 --no-true-positives --out report.csv

python gatekeeper_validate.py --rest-url https://portal.castsoftware.com/VINCIENERGIES_CODEX_HDED/rest --domain AED --user codex --password Vinci_Energie$123 --app CODEX --rule-ids 7884,7526,7788,8028  --per-rule-limit 200 --no-true-positives --out new_rules.csv

rem python gatekeeper_validate.py --rest-url https://portal.castsoftware.com/VINCIENERGIES_CODEX_HDED/rest --domain AED --app CODEX --user codex --password Vinci_Energie$123 --coverage --out report.csv
rem python gatekeeper_validate.py --url http://imaging:8283/mcp/gatekeeper --api-key $IMAGING_KEY --app MyApp --source-root .\src_test --rule-ids auto --limit 50 --out report.csv

