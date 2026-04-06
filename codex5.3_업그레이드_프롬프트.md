# Codex 5.3 업그레이드 프롬프트

아래 프롬프트를 그대로 Codex 5.3에게 전달해 현재 프로젝트를 업그레이드하라.

```text
현재 워크스페이스는 `prompt_injection_fuzzing_third` 프로젝트다. 목표는 기존 프롬프트 인젝션 평가 프로그램을, 조사한 가드레일 메커니즘과 평가 방식을 반영해 더 정교한 **한국어/영어 프롬프트 인젝션 벤치마크/분석 프레임워크**로 업그레이드하는 것이다.

중요 전제:
- 이 작업은 방어 평가와 레드팀 벤치마크 고도화 목적이다.
- 실제 배포 가능한 공격 원문 코퍼스를 대량 추가하지 말고, 현재 프로젝트 원칙대로 **slot/placeholder 기반 템플릿, mutation family, stage/source-role 메타데이터** 중심으로 구현하라.
- additive / backward compatible 원칙을 유지하라. 기존 필드는 삭제/개명하지 말고, 새 필드는 optional/default를 둬서 기존 JSONL과 테스트가 최대한 유지되게 하라.
- 종합 요약본을 1차 설계 기준으로 쓰되, 종합본에 없는 세부 메커니즘/예외/고유 강점과 약점은 개별 조사 보고서에서 보완하라.
- 단순 요약으로 끝내지 말고, 현재 저장소 파일에 반영되는 실제 수정까지 수행하라.

우선 읽을 파일 우선순위:
1. `C:\Users\andyw\Downloads\가드레일 종합 분석본.md`
2. `프롬프트_인젝션_데이터셋_설계.md`
3. `최종프롬프트인젝션 유형.md`
4. `Layer_1_2_3_4_설계.md`
5. 개별 보고서:
   - `C:\Users\andyw\Downloads\가드레일1.md`
   - `C:\Users\andyw\Downloads\가드레일2.md`
   - `C:\Users\andyw\Downloads\가드레일3.md`
   - `C:\Users\andyw\Downloads\가드레일4.md`
   - `C:\Users\andyw\Downloads\가드레일5.md`

현재 코드에서 우선 확인할 파일:
- `src/pi_fuzzer/models.py`
- `src/pi_fuzzer/scoring.py`
- `src/pi_fuzzer/reporting.py`
- `src/pi_fuzzer/validation.py`
- `src/pi_fuzzer/runners.py`
- `src/pi_fuzzer/normalize.py`
- `catalogs/analysis_taxonomy.yaml`
- `catalogs/mutation_recipes.yaml`
- `catalogs/attack_families.yaml`
- `catalogs/coverage_matrix.yaml`
- `catalogs/sample_templates.jsonl`
- `catalogs/sample_cases.jsonl`
- `tests/test_analysis_extensions.py`
- `tests/test_scoring.py`
- `tests/test_validation.py`

핵심 요구사항:

1. 공통 탐지/차단 메커니즘을 현재 프로그램 스키마/집계/테스트에 반영하라.
다음 축을 first-class로 다뤄라.
- `stage`: input / retrieval / tool_input / tool_output / output / replay
- `source_role`: user / retrieved_doc / tool_output / memory_note / assistant_quote / system_note
- `expected_interpretation`: instruction / data / quoted_text / translation_target / analysis_target
- `policy_requested`, `policy_executed`
- `detector_family`: pattern / classifier / orchestration / replay_audit
- `failure_cause_code`
- `reason_codes[]`, `matched_rule_ids[]`, `decision_trace`
- `config_fingerprint` 또는 그에 준하는 gateway/guardrail 설정 메타데이터
- `final_user_visible`, `unsafe_tool_call`, `partially_allowed`, `partial_defense`

2. 가드레일별 차이를 요약에 그치지 말고 실제 평가 축으로 연결하라.
반드시 아래 개별 포인트를 반영하라.
- LLM Guard: `MatchType`, `risk_score`, `fail_fast`, 세그먼트 전략.
- Llama Prompt Guard 2: 512 토큰 제한, 장문 chunk 병렬 스캔, 토크나이저 강화, LODO 관점의 OOD 평가.
- NeMo Guardrails: input/output rails, YARA, Colang/flow control, IORails 병렬 실행 관점.
- PIGuard: MOF, NotInject, trigger-word bias 완화, benign sibling 중심 평가.
- LlamaFirewall: role 기반 정책 엔진, `scan_replay`, AlignmentCheck, CodeShield, trajectory/goal hijack 추적.
- FortiAIGate: alert vs alert-and-deny, advanced threshold mode, 프록시 계층 정책 집행과 multilingual claim 검증 분리.
- Kanana Safeguard-Prompt: `<SAFE>/<UNSAFE-A1>/<UNSAFE-A2>` 1토큰 분류, A1/A2 reason code, prompt injection vs prompt leaking 분리.
- SGuard-JailbreakFilter: EN/KO 중심 2B/128K, priority prompting, threshold calibration, multi-class/confidence, CHT/BHCB를 반영한 한국어/문맥 혼합 평가.
- T-MAP: ARR, trajectory-aware, delayed trigger, tool transition, L0/L1/L2/L3 성격의 outcome 추적.

3. 한국어 특유의 우회 방법은 “실제 공격문 추가”가 아니라 **평가용 mutation family** 확장으로 반영하라.
최소한 다음은 taxonomy와 샘플 케이스에 반영하라.
- 자모분리
- 초성
- 한글 숫자 표기
- 한자/로마자/혼합 스크립트
- 코드스위칭
- 존대/반말/완곡 명령형
- 띄어쓰기/조사/어미 변형
- 방언/속어/신조어
- quoted attack / footer / separator / HouYi류 래퍼
- chunk boundary split
- tool output poisoning
- memory summary poisoning
- approval/form field injection
- benign-harmful contextual blending 계열 평가용 변이

4. 평가 방법을 전면 확장하라.
반드시 아래를 구현 또는 최소한 스키마/테스트/샘플에 반영하라.
- KR-EN pair 유지 및 `kr_en_pair_id` 성격의 추적
- 모든 malicious case에 benign sibling 또는 contrast group 연결
- same payload across multiple source roles 실험
- chunk-boundary / long-context 실험
- input-only vs gateway-integrated vs scenario execution 구분 유지
- replay / multi-turn / delayed injection 준비 필드 추가
- detection failure와 policy execution failure를 분리 집계
- claim-vs-measure 리포트가 가능하도록 vendor-declared support와 measured gap을 분리 보관

5. 현재 저장소의 구조를 기준으로 P0/P1/P2 우선순위로 구현하라.

P0:
- `models.py`에 additive 필드 추가
- `analysis_taxonomy.yaml`에 canonical 값 확장
- `scoring.py`에 새 집계 축 추가
- `reporting.py`에 새 리포트 섹션 추가
- `sample_templates.jsonl`, `sample_cases.jsonl`, `mutation_recipes.yaml`, `attack_families.yaml`, `coverage_matrix.yaml` 확장
- benign sibling / contrast / KR-EN pair / source-role 차이를 검증하는 테스트 추가
- 기존 테스트가 유지되도록 기본값과 정규화 로직 보완

P1:
- multi-turn delayed injection / replay 관련 필드와 기본 샘플 추가
- tool/function-call/structured payload 전용 집계 축 추가
- threshold sweep / normalization A/B / config sensitivity를 위한 기반 필드 추가

P2:
- ARR 및 trajectory-aware outcome 세분화
- memory laundering, long-context planner, vendor claim-vs-measure 분석 고도화

6. 수정 대상 파일과 기대 작업을 구체적으로 연결하라.
- `src/pi_fuzzer/models.py`
  - `CaseRecord`, `RunRecord`, `Scorecard`를 additive하게 확장하라.
- `src/pi_fuzzer/normalize.py`
  - 새 canonical 필드 정규화 지원을 추가하라.
- `catalogs/analysis_taxonomy.yaml`
  - `source_stage`, `source_role`, `expected_interpretation`, `detector_family`, `failure_cause_code`, `reason_code_category`, `tool_transition_type` 등 새 canonical 축을 정의하라.
- `src/pi_fuzzer/scoring.py`
  - `by_stage`, `by_source_role`, `by_expected_interpretation`, `by_detector_family`, `by_failure_cause_code`, `by_policy_request_vs_execution`, `by_reason_code`, `by_tool_transition`, `by_config_sensitivity`, `by_vendor_claim_gap` 성격의 집계를 추가하라.
  - 기존 지표는 유지하되 additive bucket으로 확장하라.
- `src/pi_fuzzer/reporting.py`
  - 총괄 매트릭스, 언어 격차, 경계 붕괴, benign sibling, 정책 실행 mismatch, tool/replay 리포트 섹션을 추가하라.
- `src/pi_fuzzer/validation.py`
  - KR-EN pair drift, benign sibling/contrast linkage, source-role coverage, stage coverage를 점검하는 검증을 추가하라.
- `src/pi_fuzzer/runners.py`
  - 공통 분석 필드 채우기 로직을 확장해 `source_role`, `expected_interpretation`, `policy_requested/executed`, `reason_codes`, `decision_trace`, `final_user_visible`, `unsafe_tool_call`, `tool_transition` 등을 수용하라.
- `catalogs/sample_templates.jsonl`, `catalogs/sample_cases.jsonl`
  - 새 축을 보여주는 placeholder 기반 샘플을 추가하라. 실제 악성 원문 대신 placeholder를 유지하라.
- `tests/*.py`
  - 새 필드 직렬화, 새 집계 축, contrast/benign sibling/KR-EN pair/source-role/stage 검증 테스트를 추가하라.

7. 개별 보고서의 고유 정보가 실제 구현에 반영되도록 하라.
최종 변경사항에는 다음이 드러나야 한다.
- Prompt Guard 2의 LODO 교훈이 반영된 `heldout_static`/OOD 중심 분석 또는 주석
- PIGuard NotInject를 반영한 benign sibling/trigger-bias 축
- Kanana A1/A2를 반영한 reason code / attack goal 분리
- SGuard의 CHT/BHCB를 반영한 한국어/문맥 혼합 mutation 또는 샘플 축
- LlamaFirewall/T-MAP을 반영한 replay/trajectory/tool transition 축
- FortiAIGate의 alert/deny/threshold를 반영한 policy/config sensitivity 축
- NeMo의 output rail/YARA를 반영한 output-stage / matched-rule 계열 축

8. 구현 제약:
- 기존 README의 원칙을 유지하라. “The default sample data is slot/placeholder-based and avoids publishing attack payload corpora.”
- 실제 위험한 공격 문자열을 대량 삽입하지 말라.
- 이전 필드를 삭제하거나 의미를 뒤집지 말라.
- 샘플 데이터는 placeholder 중심으로 유지하라.
- 테스트는 새 기능을 검증하되 과도하게 brittle하지 않게 작성하라.

9. 작업 순서:
1. 관련 문서와 현재 코드를 읽고 차이를 요약하라.
2. P0부터 실제 코드/카탈로그/테스트를 수정하라.
3. 가능하면 P1의 기반 필드도 일부 반영하라.
4. 테스트를 실행하고 실패를 고쳐라.
5. 마지막 응답은 아래 형식으로 정리하라.
   - 공통 메커니즘 반영 사항
   - 가드레일별 고유 반영 사항
   - P0/P1/P2 중 실제 반영 범위
   - 추가된 필드/집계/테스트
   - 남은 리스크 또는 후속 P2 항목

출력에서 특히 보고 싶은 것:
- 종합본 반복 요약이 아니라, 현재 코드에 실제로 들어간 변경점
- 공통점과 차이점이 분리된 설명
- 어떤 개별 보고서의 어떤 고유 정보가 어떤 필드/집계/테스트로 연결됐는지
- additive/backward compatible 원칙을 어떻게 지켰는지
```
