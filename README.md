# PI Fuzzer 현재 상태 가이드 (수정: 2026-04-08 18:46:03 KST)

`PI Fuzzer`는 프롬프트 인젝션 벤치마크 패키지를 빌드하고, 패키지를 검증하고, L1/L2/L3 기준 실행 결과를 스코어링과 리포팅까지 이어서 다루는 경량 툴킷이다. 현재 저장소의 기본 샘플 카탈로그는 공개 배포용 placeholder-only 원칙을 유지하며, 실제 공격 페이로드 코퍼스를 싣지 않는다.

## 이 저장소가 현재 하는 일

- `build`: `catalogs/sample_templates.jsonl`, `catalogs/sample_cases.jsonl`을 읽어 템플릿, 케이스, dedup drop, manifest를 패키지로 생성한다.
- `validate`: template 참조 무결성, pair invariant, split contamination, KR-EN link, benign sibling/contrast, source-role/stage linkage, coverage profile 위반 여부를 점검한다.
- `ingest-public`: `bipia`, `llmail-inject`, `injecagent`, `agentdojo`, `pint-xstest` 입력을 내부 스키마로 정규화한다.
- `run`: 현재 실행 가능한 레이어는 `L1`, `L2`, `L3`다. `L3`는 로컬 시나리오 타깃으로 바로 실행할 수 있고, `L1`/`L2`는 HTTP 타깃 설정도 포함한다.
- `score`: run JSONL을 읽어 detection, outcome, gateway loss, 정책 실행 불일치, replay/tool-transition, vendor claim gap 등을 집계한다.
- `report`: scorecard JSON을 Markdown/CSV로 변환한다.

현재 구현 범위는 P0/P1까지다. P2는 문서 하단의 후속 backlog로 분리되어 있으며, 현재 메인 흐름에 포함되지 않는다.

## 현재 구현 범위

- P0 완료
- additive 스키마 확장: `source_role`, `expected_interpretation`, `policy_requested`, `detector_family`, `failure_cause_code`, `reason_codes`, `matched_rule_ids`, `decision_trace`, `config_fingerprint`, `tool_transition_type` 등이 `TemplateRecord`, `CaseRecord`, `RunRecord`, `Scorecard`에 반영되어 있다.
- canonical taxonomy: `catalogs/analysis_taxonomy.yaml`이 `source_stage`, `source_role`, `expected_interpretation`, `policy_mode`, `policy_execution`, `detector_family`, `failure_cause_code`, `reason_code_category`, `tool_transition_type`, `final_user_visible`, `config_sensitivity`, `vendor_claim_gap`를 정규화한다.
- validation/dedup: pair drift, split contamination, KR-EN pair link, benign sibling/contrast, source-role/stage coverage, structured/hybrid dedup이 구현되어 있다.
- scoring/reporting: `by_source_role`, `by_expected_interpretation`, `by_detector_family`, `by_failure_cause_code`, `by_policy_request_vs_execution`, `by_raw_policy_action`, `by_reason_code`, `by_tool_transition`, `by_config_sensitivity`, `by_vendor_claim_gap`, `by_contrast_group_outcome`, `by_guard_stage_alignment` 집계가 구현되어 있다.
- sample catalog: placeholder-only 원칙 아래 KR/EN pair, benign sibling, replay, tool-transition, Korean mutation 축이 샘플 데이터에 반영되어 있다.

- P1 완료
- replay/tool-transition 축: `source_stage=replay`, `tool_transition_type=replay_to_tool`, `replay_window`, `delayed_injection_turn`, `replay_turn_index`, `delayed_trigger_fired`가 스키마와 샘플 케이스에 반영되어 있다.
- structured payload/tool misuse 축: `structured_payload_type`, `tool_input`, `tool_output`, `approval_form` 계열 시나리오가 샘플 템플릿/케이스와 coverage profile에 반영되어 있다.
- config sensitivity 준비 축: `threshold_profile`, `normalization_variant`, `config_fingerprint`, `vendor_declared_support`, `vendor_declared_supported`가 스키마와 scorecard 집계에 반영되어 있다.

## 빠른 시작

### 1. 설치

```bash
python -m pip install -e .
```

### 2. 패키지 빌드

```bash
pifuzz build --config configs/build_dev.yaml --out packages/dev_release
```

출력물은 `templates.jsonl`, `cases.jsonl`, `dedup_drops.jsonl`, `manifest.json`이다.

### 3. 패키지 검증

```bash
pifuzz validate --package packages/dev_release --config configs/build_dev.yaml
```

`--config`를 함께 주면 coverage profile 정의와 위반 여부까지 같이 확인한다.

### 4. 기본 실행

외부 HTTP 엔드포인트 없이 바로 재현 가능한 기본 흐름은 `L3 + scenario_local` 조합이다.

```bash
pifuzz run --layer L3 --package packages/dev_release --target configs/targets/scenario_local.yaml --out runs/l3_local
```

`L1`은 `configs/targets/text_http.yaml`, `L2`는 `configs/targets/gateway_http.yaml`를 사용한다. 이 둘은 실제 HTTP 엔드포인트가 필요하다.

### 5. 스코어링

```bash
pifuzz score --runs runs/l3_local --package packages/dev_release --config configs/build_dev.yaml --out reports/scorecard.json
```

`--runs`는 run JSONL 파일 하나 또는 run 디렉터리 전체를 받을 수 있다.
`--config`를 함께 주면 `validate_package()` 결과에서 coverage 요약과 `validation_ok`를 같이 기록한다.

### 6. 리포트 생성

```bash
pifuzz report --score reports/scorecard.json --md reports/report.md --csv reports/results.csv
```

## P0/P1에서 추가된 핵심 분석 축

- 입력 해석 축: `source_stage`, `source_role`, `expected_interpretation`
- 정책 비교 축: `policy_requested`, `policy_executed`, `raw_policy_action`
- 탐지 원인 축: `detector_family`, `failure_cause_code`, `reason_codes`, `matched_rule_ids`, `decision_trace`
- 설정 민감도 축: `config_fingerprint`, `threshold_profile`, `normalization_variant`
- 출력/영향 축: `final_user_visible`, `unsafe_tool_call`, `partially_allowed`, `partial_defense`
- replay/tool-transition 축: `tool_transition_type`, `replay_window`, `delayed_injection_turn`, `replay_turn_index`, `delayed_trigger_fired`
- 비교 실험 축: `kr_en_pair_id`, `benign_sibling_id`, `contrast_group_id`, `paired_case_role`

주의할 점이 하나 있다. 샘플 카탈로그의 모든 행이 이 필드를 전부 직접 채우는 것은 아니다. 현재 러너는 legacy 성격의 입력/출력 행에 대해 `entry_point`, `source_stage`, `attack_subfamily`를 이용해 `source_role`, `expected_interpretation`, `tool_transition_type`를 기본값으로 보강하고, 이후 taxonomy 기준으로 정규화한다.

## dedup / validation / coverage enforcement

- dedup 모드
- `structured_only`: exact hash와 structural fingerprint만 사용한다. 현재 `configs/build_dev.yaml` 기본값이다.
- `hybrid_mandatory`: exact hash, structural fingerprint, token-count cosine similarity 기반 near-dup 제거를 모두 사용한다. 현재 `configs/build_release_heldout.yaml` 기본값이며 release build에서 강제된다.

- validation 항목
- `validate_pair_invariants`: `user_goal`, `protected_asset`, `forbidden_action`, `tool_scope`, `entry_point`, `severity`가 KR/EN pair에서 drift 되지 않는지 확인한다.
- `validate_split_contamination`: 같은 `semantic_equivalence_group`가 여러 split에 동시에 들어가지 못하게 막고, group이 비어 있으면 `template_id`를 fallback 키로 쓴다.
- `validate_analysis_linkage`: `kr_en_pair_id`, `benign_sibling_id`, `contrast_group_id`, `source_role`, `expected_interpretation`, replay stage 규칙을 확인한다.

- coverage enforcement
- `coverage_gate.profiles`는 build/validate 시 사용할 프로파일 목록이다.
- 각 profile은 `required_dims`, `min_per_cell`, `filters`, `required_values`, `required_combinations`, `enforce_cartesian`을 가질 수 있다.
- `required_values`는 특정 값이 최소 몇 번 이상 등장해야 하는지 보장한다.
- `required_combinations`는 특정 조합이 반드시 존재해야 하는 cell을 강제한다.
- `required_dims + min_per_cell`만으로는 이미 관측된 cell의 최소 개수만 검사한다. 비어 있는 cartesian 조합까지 자동으로 강제하지는 않으며, 그 경우 `required_combinations` 또는 `enforce_cartesian`이 추가로 필요하다.
- 현재 기본 build config는 `release_default`, `p0_stage_role`, `p1_replay_tool_transition` 세 프로파일을 사용한다.
- release mode coverage는 `heldout_static`, `adaptive` split만 대상으로 적용된다. dev validation은 모든 split을 본다.

## 샘플 카탈로그 현재 상태

- shipped sample은 현재 `24`개 template, `36`개 case로 구성된다.
- 모든 sample template/case는 `<...PLACEHOLDER>` 형태의 slot만 포함한다.
- KR/EN 연결은 두 방식이 함께 있다.
- 기본 bilingual/control 연결은 `paired_case_id`로 유지된다.
- explicit `kr_en_pair_id`는 현재 P1 replay pair와 structured payload pair에 적용되어 있다.
- benign sibling은 현재 replay delayed trigger 축에 구현되어 있다.
- replay/tool-transition 값은 현재 `replay_to_tool`, `user_to_tool`이 샘플 케이스에 실려 있다.
- `attack_families.yaml`은 샘플보다 넓은 분류 집합을 담고 있다. 예를 들어 `repo_coding_agent_injection`, `adaptive_fuzzing`, `config_sensitivity_probe`는 taxonomy에는 있지만 기본 sample template에는 아직 실려 있지 않다.

## build / validate / score / report 흐름

```text
sample/public input
-> build
-> validate
-> run (L1/L2/L3)
-> score
-> report
```

- `build`는 패키지를 만든다.
- `validate`는 template 참조 무결성, pair/linkage, split contamination, coverage 위반을 검증한다.
- `run`은 case를 실행해서 run JSONL과 transcript를 남긴다.
- `score`는 run JSONL과 package case 메타데이터를 결합해 scorecard를 만들고, `--config`가 있으면 validate 기반 coverage 요약도 함께 남긴다.
- `report`는 scorecard JSON을 사람용 Markdown과 CSV로 변환한다.

## 구현과 해석에서 주의할 점

- CLI에서 실행 가능한 layer는 `L1`, `L2`, `L3`뿐이다.
- case 메타데이터의 `execution_layer=L4_e2e_rag`는 현재 실행 레이어가 아니라 분석/라벨링 축이다.
- default sample은 공개 배포 가능한 placeholder-only 데이터다.
- 실제 공격 코퍼스를 넣으려면 별도 source와 redistribution 정책을 명시해야 한다.

## P2 backlog

- ARR / trajectory 고도 분석
- memory laundering 심화 축과 장문맥 planner 계열 고도화
- vendor claim-vs-measure 비교의 정교화
- coverage policy 강화 여부와 어떤 profile을 release 기본으로 올릴지에 대한 후속 결정
