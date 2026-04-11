# test2_1: 실제 Prompt Injection 퍼지 코퍼스

`test2`가 명세 고정 단계였다면, `test2_1`은 실제 퍼지 데이터를 생성한 단계다.  
이 폴더는 `test2/spec` 스키마를 그대로 따르는 EN/KO prompt injection fuzz 세트와 검증 스크립트를 포함한다.

## 구성

- `generate_fuzz_dataset.py`
- `validate_test2_1.py`
- `output/pi_master_canonical.jsonl`
- `output/pi_rendered_cases.jsonl`
- `output/pi_layer1_input.json`
- `output/pi_layer1_output.json`
- `output/pi_layer2_gateway.json`
- `output/pi_layer3_llm.json`
- `output/pi_layer4_rag_docs.jsonl`
- `output/pi_layer4_rag_queries.jsonl`
- `output/pi_hard_negative_eval.json`
- `output/pi_stats.json`

## 생성 방법

프로젝트 루트에서 실행:

```bash
python test2_1/generate_fuzz_dataset.py
```

옵션:

```bash
python test2_1/generate_fuzz_dataset.py --ko-native-count 20 --hard-negative-count 20
```

## 검증 방법

```bash
python test2_1/validate_test2_1.py
```

검증 항목:

- `test2/spec/*.schema.json` 기반 스키마 검증
- `family_id` split hygiene
- `PAIR-*` EN/KO 짝 일관성
- `KO-NATIVE-*` 분리 태깅
- hard negative 비율 최소 20%
- KO hard negative 최소 50%
- Layer export 커버리지
  - surface: `direct_user`, `indirect_document`, `indirect_email`, `indirect_repo`, `multi_turn_memory`
  - goal: `tool_redirection` 포함
  - hard negative 포함
- `pi_stats` 필수 집계 키 포함

## 데이터 정책

- 모든 케이스는 synthetic marker 기반이다.
- 실제 PII, 실제 비밀값, 실제 계정/토큰은 포함하지 않는다.
- 한국어는 `EN-KO paired + KO-native`를 분리 운영한다.
