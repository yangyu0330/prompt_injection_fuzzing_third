# PI Fuzzer

Prompt injection benchmark release toolkit with:

- dataset builder (`build`, `validate`)
- public benchmark ingestion (`ingest-public`)
- baseline runners (`L1`, `L2`, `L3`)
- scorers (`score`)
- reporters (`report`)
- gateway-independent HTTP dispatch (`dispatch-http`)

## Quick start

```bash
python -m pip install -e .
pifuzz build --config configs/build_dev.yaml --out packages/dev_release
pifuzz validate --package packages/dev_release --config configs/build_dev.yaml
pifuzz run --layer L1 --package packages/dev_release --target configs/targets/scenario_local.yaml --out runs/l1
pifuzz score --runs runs/l1 --package packages/dev_release --out reports/scorecard.json
pifuzz report --score reports/scorecard.json --md reports/report.md --csv reports/results.csv
```

The default sample data is slot/placeholder-based and avoids publishing attack payload corpora.
