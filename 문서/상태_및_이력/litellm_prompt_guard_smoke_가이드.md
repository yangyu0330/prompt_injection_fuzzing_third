# LiteLLM + Llama Prompt Guard 스모크 가이드 (수정: 2026-04-10)

## 목표
- `L1`: `meta-llama/Llama-Prompt-Guard-2-86M` 단독 탐지 확인
- `L2`: `LiteLLM gateway + Prompt Guard` 결합 상태에서 `allow/block` 차이 확인

## 사전 조건
- HF 계정이 `meta-llama/Llama-Prompt-Guard-2-86M` gated access 승인 상태
- Python 3.11+

## 설치
```bash
python -m pip install -e ".[guardrail,dev]"
```

## 1) Prompt Guard 로컬 서버 실행
```bash
pifuzz serve-prompt-guard --host 127.0.0.1 --port 8011 --model-id meta-llama/Llama-Prompt-Guard-2-86M
```

빠른 로컬 검증만 필요하면 mock 모드:
```bash
pifuzz serve-prompt-guard --use-mock
```

## 2) LiteLLM Proxy 실행
```bash
litellm --config configs/litellm/prompt_guard_proxy.yaml --port 4000
```

## 3) Gateway Probe 실행
```bash
pifuzz serve-gateway-probe --host 127.0.0.1 --port 8012 --litellm-base-url http://127.0.0.1:4000
```

## 4) 단건 dispatch 확인
```bash
pifuzz dispatch-http --target configs/targets/text_http_llama_prompt_guard.yaml --package packages/dev_release --case-id CASE-000001
```

```bash
pifuzz dispatch-http --target configs/targets/gateway_http_litellm_prompt_guard.yaml --package packages/dev_release --case-id CASE-000001 --enforcement-mode block
```

## 5) L1/L2 스모크 실행
```bash
pifuzz run --layer L1 --package packages/dev_release --target configs/targets/text_http_llama_prompt_guard.yaml --out runs/l1_prompt_guard --enforcement-modes allow,block
```

```bash
pifuzz run --layer L2 --package packages/dev_release --target configs/targets/gateway_http_litellm_prompt_guard.yaml --out runs/l2_litellm_prompt_guard --enforcement-modes allow,block
```

## 6) 결과 집계
```bash
pifuzz score --runs runs/l1_prompt_guard runs/l2_litellm_prompt_guard --package packages/dev_release --out reports/scorecard_litellm_prompt_guard.json
```

```bash
pifuzz report --score reports/scorecard_litellm_prompt_guard.json --md reports/report_litellm_prompt_guard.md --csv reports/results_litellm_prompt_guard.csv
```
