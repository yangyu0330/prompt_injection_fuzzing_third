# codex4차 Deprecated 안내 (수정: 2026-04-08 13:41:26 KST)

이 문서는 현재 구현 이전 단계의 계획 메모였고, 현재 저장소와 충돌하는 설명이 많아 source of truth로 사용하지 않는다.

현재 기준으로 바로잡아야 하는 핵심만 남긴다.

- 실행 레이어: CLI에서 실제 실행 가능한 layer는 `L1`, `L2`, `L3`뿐이다.
- `execution_layer=L4_e2e_rag`는 현재 case 분석 라벨이지, 실행 가능한 CLI layer가 아니다.
- 데이터 축: 현재는 `source_role`, `expected_interpretation`, `policy_requested`, `policy_executed`, `raw_policy_action`, `detector_family`, `failure_cause_code`, `reason_codes`, `matched_rule_ids`, `decision_trace`, `config_fingerprint`, `tool_transition_type`, replay 관련 필드가 실제 스키마에 반영돼 있다.
- gate 체계: 현재 build/validate는 `coverage_gate.profiles`, `required_values`, `required_combinations`, hybrid dedup, KR-EN pair/benign sibling/source-role linkage validation을 사용한다.
- sample 원칙: 현재 기본 샘플 카탈로그는 placeholder-only다.

최신 기준은 아래 문서를 본다.

- `README.md`
- `프롬프트_인젝션_데이터셋_설계.md`
- `문서/상태_및_이력/codex5.3_업그레이드_프롬프트.md`
