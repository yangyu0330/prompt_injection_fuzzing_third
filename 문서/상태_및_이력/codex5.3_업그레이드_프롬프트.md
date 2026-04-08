# Codex 5.3 업그레이드 상태 문서 (수정: 2026-04-08 13:41:26 KST)

이 문서는 더 이상 명령형 작업 지시문이 아니다. 현재 저장소에 반영된 P0/P1 결과와 남은 P2를 기록하는 상태 문서다. 구현 기준은 코드와 카탈로그다.

## 반영된 내용

### P0 완료

- 스키마 확장 완료
- `src/pi_fuzzer/models.py`에 `source_role`, `expected_interpretation`, `policy_requested`, `policy_executed`, `raw_policy_action`, `detector_family`, `failure_cause_code`, `reason_codes`, `matched_rule_ids`, `decision_trace`, `config_fingerprint`, `tool_transition_type` 계열이 반영되어 있다.

- canonical taxonomy 반영 완료
- `catalogs/analysis_taxonomy.yaml`에 source/policy/detector/failure/tool-transition/final-visible/config-sensitivity/vendor-claim canonical 값이 정의되어 있고, `src/pi_fuzzer/normalize.py`가 이를 사용한다.

- validation/dedup 고도화 완료
- KR-EN pair link, benign sibling/contrast, source-role/stage linkage validation이 `src/pi_fuzzer/validation.py`에 반영되어 있다.
- structural fingerprint가 replay/tool-transition 및 비교 envelope를 포함하도록 확장되어 있다.
- release build는 `hybrid_mandatory` dedup을 요구한다.

- coverage gate 확장 완료
- `coverage_gate.profiles`, `required_values`, `required_combinations`가 `src/pi_fuzzer/build.py`와 `catalogs/coverage_matrix.yaml`에 반영되어 있다.
- 기본 build config는 `release_default`, `p0_stage_role`, `p1_replay_tool_transition`를 사용한다.

- scoring/reporting 확장 완료
- `src/pi_fuzzer/scoring.py`가 `by_source_role`, `by_expected_interpretation`, `by_detector_family`, `by_failure_cause_code`, `by_policy_request_vs_execution`, `by_raw_policy_action`, `by_reason_code`, `by_tool_transition`, `by_config_sensitivity`, `by_vendor_claim_gap`, `by_contrast_group_outcome`, `by_guard_stage_alignment`를 집계한다.
- `src/pi_fuzzer/reporting.py`가 이 집계를 Markdown 표와 CSV로 노출한다.

- sample catalog 확장 완료
- `catalogs/sample_templates.jsonl`, `catalogs/sample_cases.jsonl`는 placeholder-only 원칙을 유지한다.
- KR/EN pair, benign sibling, Korean mutation, replay delayed trigger, structured payload misuse 예시가 실제 sample에 들어 있다.

- 테스트 반영 완료
- `tests/test_validation.py`, `tests/test_build_coverage_profiles.py`, `tests/test_scoring.py`, `tests/test_analysis_extensions.py`, `tests/test_catalog_stage_consistency.py`가 위 기능을 고정한다.

### P1 완료

- replay/tool-transition 필드 반영 완료
- `replay_window`, `delayed_injection_turn`, `replay_turn_index`, `delayed_trigger_fired`, `tool_transition_type`가 스키마와 sample, scorecard에 반영되어 있다.

- structured payload/function-call misuse 반영 완료
- `structured_payload_type`, `tool_input`, `tool_output`, `approval_form` 축이 sample case와 coverage profile에 반영되어 있다.

- config sensitivity 준비 필드 반영 완료
- `threshold_profile`, `normalization_variant`, `config_fingerprint`, `vendor_declared_support`, `vendor_declared_supported`가 스키마와 scorecard에 반영되어 있다.

## 현재 운영 기준

- 구현 기준은 문서가 아니라 코드다.
- shipped sample은 placeholder-only다.
- CLI 실행 layer는 현재 `L1`, `L2`, `L3`뿐이다.
- case 메타데이터의 `execution_layer=L4_e2e_rag`는 실행 레이어가 아니라 분석 라벨이다.

## P2만 남은 항목

- ARR / trajectory 고도 분석
- memory laundering 심화
- vendor claim-vs-measure 고도화
- coverage policy 강화 여부와 어떤 profile을 release 기본으로 더 올릴지에 대한 결정

## 현재 참고할 문서

- `README.md`
- `프롬프트_인젝션_데이터셋_설계.md`
- `문서/상태_및_이력/codex4차.md`는 deprecated 안내만 남긴 상태이며 source of truth가 아니다.
