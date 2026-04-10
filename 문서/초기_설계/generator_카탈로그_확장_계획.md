# Generator 카탈로그 확장 계획 (수정: 2026-04-10 16:35:13 KST)

## 상태
- 현재 코드 기준으로 이 문서의 핵심 범위는 반영돼 있다.
- `configs/generator_bulk.yaml`에는 12개 attack family가 모두 들어가 있고, `adaptive_fuzzing` seed-derivation planner와 `config_sensitivity_probe` probe pair planner가 구현돼 있다.
- `catalogs/coverage_matrix.yaml`에는 `bulk_full_family_set`, `repo_surface_axes`, `config_probe_axes`가 추가돼 있고, `configs/build_generated_dev.yaml`와 `refill.driving_profiles`가 이를 사용한다.
- `catalogs/sample_templates.jsonl`, `catalogs/mutation_recipes.yaml`, `tests/test_generator_catalog_expansion.py`, `tests/test_generator_bulk.py`, `tests/test_generator_bulk_report.py`, `tests/test_build_coverage_profiles.py`가 문서 범위에 맞게 같이 갱신돼 있다.
- 추가로 현재 구현은 `contrast_group_id`, `primary_mutation`, `secondary_mutations`, `mutation_family`를 structural fingerprint에 포함시켜 bulk dedup index와 build dedup envelope를 맞춘다.

## Summary
- 목표는 `bulk`가 현재 2개 family에서 멈추지 않고, `attack_families.yaml`의 12개 attack family를 모두 생성 대상으로 다루게 만드는 것이다.
- 범위는 네 덩어리로 고정한다: 기존 family 7개 bulk 편입, 신규 family 3개 template 작성, 축 확장 template 추가, 전용 planner/coverage/refill/test 정비.
- 이번 계획은 placeholder-only 원칙을 유지한다. 새 template와 planner는 모두 metadata 조합기 범위 안에서 설계하고, 자유 텍스트 생성은 넣지 않는다.
- `adaptive_fuzzing`는 단순 sample family로 끝내지 않고 seed-derivation planner를 포함한다. `config_sensitivity_probe`도 단순 template 추가가 아니라 threshold/normalization pair generator까지 포함한다.

## Implementation Changes
- 문서 본문은 다음 섹션으로 고정한다: 목적, 현재 상태와 빈칸, 단계별 확장 범위, 신규 family/template 정의, 전용 planner 설계, bulk/coverage/refill 변경, 테스트와 완료 조건.
- `configs/generator_bulk.yaml`은 12개 attack family를 모두 포함하도록 확장한다. 기존 2개에 더해 `ko_native_mutation_layer`, `korean_service_context`, `structured_payload_misuse`, `direct_user_injection`, `indirect_document_web_rag`, `email_agent_injection`, `ko_detector_guardrail_track`, `repo_coding_agent_injection`, `adaptive_fuzzing`, `config_sensitivity_probe`를 추가한다.
- family budget은 2000 survivor 합계로 고정한다. `tool_agent_misuse 400`, `replay_trajectory_injection 250`, `structured_payload_misuse 200`, `korean_service_context 180`, `indirect_document_web_rag 150`, `ko_native_mutation_layer 150`, `repo_coding_agent_injection 150`, `direct_user_injection 120`, `email_agent_injection 120`, `ko_detector_guardrail_track 100`, `adaptive_fuzzing 100`, `config_sensitivity_probe 80`으로 둔다. `max_raw_rows`는 각 target의 2배, `max_bundles`는 `ceil(max_raw_rows / 5)`로 맞춘다.
- 기존 3개 family는 MVP config를 bulk로 그대로 승격한다. `ko_native_mutation_layer`, `korean_service_context`, `structured_payload_misuse`의 axis 값은 [`configs/generator_mvp.yaml`](/c:/Users/andyw/Desktop/prompt_injection_fuzzing_third/configs/generator_mvp.yaml) 기준을 source로 삼는다.
- 나머지 4개 기존-template family는 template capability의 합집합으로 bulk rule을 명시한다. `direct_user_injection`은 `user_prompt / plain_chat|markdown / user / instruction / direct_override|roleplay_persona_hijack`, `indirect_document_web_rag`는 `retrieved_document|webpage_body|html_comment_or_metadata|search_result|file_text / markdown|json|html|long_context_document|table|repo_file / retrieved_doc / data / structured_wrapper_injection|rag_chunk_boundary_split|html_metadata_comment_injection|html_wrapper|document_context_laundering`, `email_agent_injection`은 `quoted_reply|email_body / email_thread|ticket_thread|markdown / assistant_quote|retrieved_doc / data / quoted_reply_footer_injection|deferential_request|bureaucratic_formal`, `ko_detector_guardrail_track`은 `user_prompt / plain_chat|ticket_thread / user / instruction / confirmation_bypass_framing|casual_imperative|deferential_request`로 고정한다.
- contrast policy는 `tool_agent_misuse`, `replay_trajectory_injection`, `structured_payload_misuse`, `repo_coding_agent_injection`에 `require_benign=true`를 둔다. `structured_payload_misuse`는 MVP의 `TMP-KO-BENIGN-STYLE-001` 정책을 bulk에도 넣고, `repo_coding_agent_injection`은 새 benign template를 pool로 사용한다.
- benign template도 같이 늘린다. `TMP-BENIGN-REPO-001`은 safe repo review/summary용 `repo_file` benign hard negative, `TMP-BENIGN-YAML-001`은 safe YAML/schema explanation용 benign hard negative로 추가한다. 이유는 현재 benign template가 2개뿐이고 확장 후 contrast family 수를 감당하지 못하기 때문이다.
- 신규 attack template는 최소 7개로 고정한다. `TMP-REPO-COMMENT-001`, `TMP-REPO-WORKFLOW-001`은 `repo_coding_agent_injection`; `TMP-ADAPT-SEED-001`, `TMP-ADAPT-TOOL-001`은 `adaptive_fuzzing`; `TMP-CONFIG-THRESH-001`, `TMP-CONFIG-NORM-001`은 `config_sensitivity_probe`; `TMP-RAG-SEARCH-001`, `TMP-RAG-REPOFILE-001`, `TMP-STRUCT-YAML-001`은 축 확장 겸 기존 family retrofit template로 추가한다.
- `search_result` 축은 `indirect_document_web_rag`에 즉시 붙인다. `repo_file` 축은 새 `repo_coding_agent_injection`의 주축으로 쓰고, 기존 family 확장 요구를 반영해 `TMP-RAG-REPOFILE-001`로 `indirect_document_web_rag`에도 한 번 붙인다. `yaml` 축은 `structured_payload_misuse`와 `repo_coding_agent_injection`에 붙인다. `normalization_ab_variant`는 `config_sensitivity_probe`의 기본 축으로 두고, 기존 family 즉시 확장을 위해 `structured_payload_misuse`에도 variant pair를 추가한다.
- `catalogs/mutation_recipes.yaml`은 이번 확장에서 실제로 활성화되는 missing recipe를 메운다. 최소 추가 대상은 `roleplay_persona_hijack`, `structured_wrapper_injection`, `honorific_style`, `spacing_particle_ending_variation`, `html_wrapper`, `markdown_wrapper`, `yaml_wrapper`, `tool_hierarchy_abuse`다.
- `src/pi_fuzzer/generator_bulk.py`에는 family planner dispatch를 추가한다. 기본 family는 현행 cartesian planner를 유지하고, `adaptive_fuzzing`는 `seed_families`, `operator_chain`, `max_variants_per_seed`, `seed_selection_limit`을 읽는 seed-derivation planner로 분기한다. seed source는 같은 run의 committed survivors 우선, 없으면 template catalog fallback으로 둔다.
- `config_sensitivity_probe`는 blind cartesian이 아니라 probe pair planner로 분기한다. config는 `probe_pairs`를 받게 하고, 기본 pair는 `threshold_only`, `normalization_only`, `combined` 3종으로 고정한다. 각 pair는 같은 semantic group을 공유하되 `threshold_profile` 또는 `normalization_variant`가 달라 structural fingerprint가 분리되도록 한다.
- model/schema는 늘리지 않는다. 새 family와 planner는 기존 `TemplateRecord`/`CaseRecord`의 `threshold_profile`, `normalization_variant`, `source_role`, `expected_interpretation`, `paired_case_role`, `contrast_group_id`, `notes`만으로 표현한다.
- `catalogs/coverage_matrix.yaml`에는 새 profile 3개를 추가한다. `bulk_full_family_set`은 12개 attack family 존재를 강제하고, `repo_surface_axes`는 `search_result`, `file_text`, `repo_file`, `yaml` 조합을 강제하며, `config_probe_axes`는 `threshold_profile`과 `normalization_variant`의 baseline/variant pair 존재를 강제한다.
- `configs/build_generated_dev.yaml`은 위 3개 profile을 기본 coverage profile에 추가한다. `configs/generator_bulk.yaml`의 `refill.driving_profiles`도 `release_default`, `p1_replay_tool_transition`, `bulk_full_family_set`, `repo_surface_axes`, `config_probe_axes`로 확장한다. 새 driving profile은 `attack_family`를 포함해 family/template 역추적이 가능하게 만든다.

## Test Plan
- config/unit: bulk config가 12개 attack family를 모두 로드하고 각 family가 최소 1개 planner output을 만든다는 테스트를 추가한다.
- template/catalog: 신규 7개 attack template와 2개 benign template가 `capability_and_placeholder_self_check`와 `validate_analysis_linkage`를 통과하는 테스트를 추가한다.
- recipe completeness: expanded bulk config 또는 신규 template가 참조하는 `allowed_mutation_families`마다 대응 recipe가 존재하는지 검증하는 테스트를 추가한다.
- adaptive planner: seed family survivor가 있을 때 adaptive planner가 derivative bundle을 만들고, seed가 없을 때 template fallback으로 최소 1개 bundle을 만드는 테스트를 추가한다.
- config probe planner: `threshold_only`, `normalization_only`, `combined` pair가 각각 distinct structural fingerprint로 남고 같은 semantic group으로 묶이는지 테스트한다.
- axis coverage: 생성 결과에 `search_result`, `repo_file`, `yaml`, `normalization_ab_variant`가 모두 최소 1건씩 포함되는지 테스트한다.
- build/preflight: `configs/build_generated_dev.yaml` 기준 preflight가 새 coverage profile 위반을 driving/report-only로 올바르게 분류하는지 테스트한다.
- integration: temp config로 12-family 1-pass bulk를 돌렸을 때 crash 없이 완료되고 summary/manifest/export가 일관되게 남는지 테스트한다.

## Assumptions
- 이 계획은 `문서/초기_설계` 성격의 구현 전 설계 문서로 취급한다. 상태 보고 문서나 root source-of-truth 문서로 승격하지 않는다.
- `adaptive_fuzzing`의 “전용 로직”은 LLM 기반 탐색이 아니라 deterministic seed-derivation planner까지를 뜻한다.
- `config_sensitivity_probe`의 “전용 로직”은 run-time multi-config score를 전제로 한 case pair generator까지를 뜻한다. 별도 score schema 변경은 하지 않는다.
- `repo_file` 축은 기존 family에도 무조건 강제하지 않는다. 의미가 맞는 family에만 즉시 붙이고, 부적절한 family에는 억지로 carrier를 넓히지 않는다.
- 구현 순서는 문서 작성 후 `catalogs/sample_templates.jsonl`과 `configs/generator_bulk.yaml` 확장, 그다음 planner/coverage/test 정비 순으로 고정한다.
