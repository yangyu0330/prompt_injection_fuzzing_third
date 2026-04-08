# Coverage 및 검증 가이드 (수정: 2026-04-08 18:46:03 KST)

이 문서는 build gate, validation, dedup, coverage enforcement를 운영 관점에서 설명한다. 현재 구현 기준 설명이며, 존재하지 않는 검사 단계는 포함하지 않는다.

## 1. build 단계 검사 순서

현재 [`src/pi_fuzzer/build.py`](src/pi_fuzzer/build.py)의 `build_package()` 순서는 아래처럼 고정돼 있다.

```text
load templates/cases
-> deterministic split assign
-> dedup
-> pair/split/analysis validation
-> coverage gate
-> package export
```

각 단계의 현재 역할은 다음과 같다.

1. 입력 로드
   - template/case JSONL을 읽는다.
   - 설정에 source path가 없으면 shipped sample catalog를 기본값으로 쓴다.
2. split 재배정
   - `semantic_equivalence_group` 또는 `template_id`를 키로 deterministic split를 다시 정한다.
3. dedup
   - build mode에 따라 `structured_only` 또는 `hybrid_mandatory`를 적용한다.
4. validation
   - pair invariant
   - split contamination
   - analysis linkage
5. coverage gate
   - named profile 목록을 순서대로 적용한다.
6. export
   - `templates.jsonl`, `cases.jsonl`, `dedup_drops.jsonl`, `manifest.json`을 쓴다.

## 2. `validate_package()`가 다시 확인하는 것

`validate_package()`는 이미 만들어진 package를 다시 열어 아래만 확인한다.

- `validate_template_references()`
- `validate_pair_invariants()`
- `validate_split_contamination()`
- `validate_analysis_linkage()`
- coverage profile 위반 여부

중요:

- `validate_package()`는 split를 다시 배정하지 않는다.
- dedup를 다시 계산하지 않는다.
- `dedup_drops.jsonl`와의 일치 여부를 검증하지 않는다.

즉 `validate_package()`는 package 내부 일관성과 coverage를 다시 보는 도구이지, build 전체를 재실행하는 도구는 아니다.

## 3. pair invariants

현재 `validate_pair_invariants()`가 비교하는 필드는 아래 여섯 개다.

- `user_goal`
- `protected_asset`
- `forbidden_action`
- `tool_scope`
- `entry_point`
- `severity`

현재 규칙:

- `paired_case_id`가 있으면 대상 row가 존재해야 한다.
- 대상 row는 다시 원래 row를 가리켜야 한다.
- 위 여섯 필드는 pair 안에서 drift 되면 안 된다.

이 검사는 기본 bilingual/control pair의 의미를 유지하기 위한 최소 조건이다.

## 4. split contamination

현재 `validate_split_contamination()`는 `semantic_equivalence_group`를 우선 키로 쓰고, 비어 있으면 `template_id`를 fallback 키로 split 집합을 본다.

- 같은 group이 여러 split에 동시에 들어가면 실패한다.
- build가 split를 group 단위로 다시 정하므로, 정상적인 build 산출물에서는 이 오류가 잘 나오지 않는다.
- 그러나 수동 편집된 package나 외부 입력 package를 validate할 때는 여전히 중요한 검사다.

## 5. KR-EN pair linkage

현재 `validate_kr_en_pair_links()`는 `kr_en_pair_id`가 채워진 row만 본다.

현재 규칙:

- pair group 안에 `ko`와 `en`이 모두 있어야 한다.
- group row 수는 최소 2개여야 한다.
- group 안의 row가 `paired_case_id`를 쓰면 반드시 같은 `kr_en_pair_id` 그룹 안을 가리켜야 한다.

주의:

- `paired_case_id`만 있고 `kr_en_pair_id`가 없는 일반 pair는 이 함수가 보지 않는다.
- 일반 pair 정합성은 `validate_pair_invariants()`가 본다.

## 6. benign sibling / contrast linkage

현재 `validate_benign_sibling_and_contrast()`는 두 종류의 규칙을 본다.

### sibling 규칙

- `benign_sibling_id` 대상이 존재해야 한다.
- sibling은 반드시 반대 `attack_or_benign`을 가져야 한다.
- 둘 다 `contrast_group_id`가 있으면 값이 같아야 한다.

### contrast group 규칙

- 같은 `contrast_group_id` 안에 attack row는 있는데 benign control이 필요하다고 판단되면 benign row가 있어야 한다.
- “benign control이 필요하다”는 현재 기준은 아래 둘 중 하나다.
  - 어떤 row가 `benign_sibling_id`를 사용함
  - 어떤 row의 `paired_case_role`이 `benign`으로 시작함

## 7. `source_stage / source_role / expected_interpretation` validation

현재 `validate_source_role_stage_coverage()`는 다음 규칙을 사용한다.

- `source_role` 또는 `expected_interpretation`가 이미 채워져 있으면 둘 다 있어야 한다.
- `source_stage`가 `retrieval`, `tool_input`, `tool_output`, `replay`이면 사실상 role/interp를 요구한다.
- `source_stage=tool_output`이면 `source_role=tool_output`이어야 한다.
- `source_stage=replay`이면 `source_role`은 `memory_note` 또는 `tool_output`이어야 한다.
- `source_stage=retrieval`이면 `source_role`은 `retrieved_doc`, `assistant_quote`, `system_note` 중 하나여야 한다.

이 검사는 “어디서 왔는가”보다 “무엇으로 읽혀야 하는가”를 package 수준에서 정리하기 위한 gate다.

## 8. `structural_fingerprint`가 포함하는 축

현재 `structural_fingerprint()`는 아래 필드를 key로 묶는다.

- `template_id`
- `attack_family`
- `attack_subfamily`
- `directness`
- `source_stage`
- `source_role`
- `expected_interpretation`
- `turn_mode`
- `entry_point`
- `carrier_context`
- `language`
- `semantic_equivalence_group`
- `kr_en_pair_id`
- `benign_sibling_id`
- `tool_transition_type`
- `replay_window`
- `delayed_injection_turn`
- `structured_payload_type`
- `threshold_profile`
- `normalization_variant`

의미:

- payload가 같아도 이 envelope가 다르면 다른 case로 남긴다.
- 현재 테스트는 같은 payload라도 `source_role`이 다르면 dedup로 제거되지 않음을 확인한다.

## 9. `dedup.mode=structured_only`와 `hybrid_mandatory` 차이

### 공통

두 모드 모두 아래 두 단계는 항상 수행한다.

- exact hash 검사
- structural fingerprint 검사

### `structured_only`

- exact hash와 structural fingerprint까지만 본다.
- 현재 `configs/build_dev.yaml` 기본값이다.

### `hybrid_mandatory`

- exact hash + structural fingerprint + token-count cosine similarity 기반 near-dup 검사까지 수행한다.
- 현재 `configs/build_release_heldout.yaml` 기본값이다.

## 10. release build에서 `hybrid_mandatory`가 강제되는 이유와 현재 동작

현재 release build는 아래 규칙을 갖는다.

- `build.mode == release`인데 `dedup.mode != hybrid_mandatory`면 build 자체가 실패한다.
- hybrid near-dup 검사는 `heldout_static`, `adaptive` split에만 적용한다.
- `dev_calibration`, `benign_hard_negative` split는 release build에서도 hybrid 대상이 아니다.

이렇게 구현된 이유는 현재 release 용도에서 heldout/adaptive 중복을 더 엄격히 줄이되, calibration/benign control은 과도하게 지우지 않기 위해서다.

## 11. `coverage_gate.profiles` 개념

현재 coverage gate는 profile 목록을 순서대로 적용한다.

각 profile은 다음 구성요소를 가질 수 있다.

| 항목 | 현재 의미 |
|---|---|
| `required_dims` | coverage cell을 구성하는 차원 |
| `min_per_cell` | 각 cell 최소 개수 |
| `filters` | 특정 subset에만 gate 적용 |
| `required_values` | 특정 축의 특정 값이 최소 몇 번 이상 있어야 하는지 |
| `required_combinations` | 특정 조합이 반드시 존재해야 하는지 |
| `enforce_cartesian` | `required_dims` 전 차원 cartesian cell을 강제할지 여부 |

중요한 구현 디테일:

- `required_dims + min_per_cell`만 쓰면 “이미 관측된 cell”의 최소 개수만 검사한다.
- 즉 빠진 cartesian 조합은 자동으로 위반이 되지 않는다.
- 빠진 조합까지 강제하려면 `enforce_cartesian=true`와 `required_values`, 또는 `required_combinations`를 같이 써야 한다.

## 12. 현재 shipped profile

현재 shipped build config는 아래 세 profile을 사용한다.

### `release_default`

- `required_dims = [language, source_stage, directness, attack_family]`
- `min_per_cell = 1`
- 기본 커버리지 존재 여부를 본다.

### `p0_stage_role`

- `required_dims = [language, source_stage, source_role, expected_interpretation]`
- `required_values`
  - `source_role`: `user`, `retrieved_doc`, `tool_output`
  - `expected_interpretation`: `instruction`, `data`
- `required_combinations`
  - `input + user + instruction`
  - `tool_input + tool_output + data`

의미:

- P0 확장 축이 package에 실제로 존재하는지 본다.

### `p1_replay_tool_transition`

- `filters.turn_mode = multi_turn`
- `required_dims = [turn_mode, source_stage, entry_point, attack_family]`
- `required_values`
  - `source_stage`: `replay`, `tool_input`
  - `entry_point`: `memory_or_summary`, `tool_output`
  - `tool_transition_type`: `replay_to_tool`, `user_to_tool`
- `required_combinations`
  - `multi_turn + replay + memory_or_summary + replay_trajectory_injection`
  - `multi_turn + tool_input + tool_output + structured_payload_misuse`

의미:

- P1 replay/tool transition 축이 실제 샘플에 포함됐는지 본다.

## 13. release mode coverage scope

현재 coverage scope는 build mode에 따라 다르다.

- dev mode: `all_splits`
- release mode: `heldout_static`, `adaptive`

현재 `validate_package()`도 config를 주면 같은 scope 규칙을 다시 따른다.

즉 release validation은 calibration과 benign_hard_negative를 coverage 대상에서 뺀다.

## 14. 운영상 `validate`를 `score`보다 먼저 돌려야 하는 이유

현재 운영 순서는 `build -> validate -> run -> score` 또는 `build -> validate -> score`로 보는 편이 안전하다.

이유는 단순하다.

- `score` CLI는 `--config`를 주면 `validate_package()`를 호출해 coverage 요약을 함께 기록한다.
- `score` CLI를 `--config` 없이 실행하면 coverage는 `checked=false`, `passed=null`로 남는다.
- `score` CLI는 `--config`가 있으면 `validate_package()`를 호출하므로 template/pair/linkage 검사를 계산한다.
- 다만 이 결과를 `score` 명령 자체의 실패 조건으로 승격하지는 않고, coverage summary의 `validation_ok` 같은 보조 정보로만 남긴다.
- malformed package라도 scorecard는 생성될 수 있다.
- `validate_package()`도 dedup는 다시 계산하지 않으므로, dedup 상태를 신뢰하려면 원래 build를 통과했는지 먼저 확인해야 한다.

즉 score 결과가 나왔다는 사실은 package 품질을 보증하지 않는다. 품질 gate는 build/validate가 담당한다.

## 관련 소스

- [`src/pi_fuzzer/build.py`](src/pi_fuzzer/build.py)
- [`src/pi_fuzzer/validation.py`](src/pi_fuzzer/validation.py)
- [`catalogs/coverage_matrix.yaml`](catalogs/coverage_matrix.yaml)
- [`tests/test_build_coverage_profiles.py`](tests/test_build_coverage_profiles.py)
- [`tests/test_validation.py`](tests/test_validation.py)
