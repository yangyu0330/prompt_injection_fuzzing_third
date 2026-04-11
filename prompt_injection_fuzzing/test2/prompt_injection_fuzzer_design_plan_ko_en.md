# 영어·한국어 Prompt Injection Fuzzer 설계 문서

작성일: 2026-04-01

## 1. 문서 목적

이 문서는 기존 PII 중심 4단계 검증 프레임워크를 프롬프트 인젝션 전용 퍼저로 재설계한 결과를 정리한 문서다. 목표는 단순한 공격 문장 모음을 만드는 것이 아니라, 영어와 한국어 환경에서 직접 공격, 간접 공격, 에이전트/tool 오용, RAG/repo 기반 간접 인젝션, hard negative까지 함께 평가할 수 있는 코퍼스와 실행 구조를 만드는 것이다.

이 설계는 아래 조건을 만족하도록 고정한다.

- 기존 `Layer 1~4` 구조는 유지한다.
- 1차 지표는 `prompt injection 탐지/차단율`로 고정한다.
- 2차 지표는 `canary leak`, `prompt leak`, `synthetic secret leak`, `tool/action redirection`, `false positive`로 둔다.
- 구현 단위는 `master canonical corpus 1개 + layer별 export 세트 + RAG/repo 문서 코퍼스 + hard negative eval 세트 + 공통 judge schema`로 고정한다.

## 2. 왜 기존 PII 프레임워크를 그대로 쓰면 안 되는가

기존 PII 프레임워크는 “입력이나 출력에 민감정보 문자열이 포함됐는가”를 중심으로 본다. 반면 프롬프트 인젝션은 아래 문제를 함께 다뤄야 한다.

- 외부 문서의 지시를 모델이 내부 지시보다 우선하는지
- detector가 공격을 놓친 뒤 LLM이 실제로 그 지시를 따르는지
- 시스템 프롬프트가 누출되는지
- synthetic secret이나 canary가 외부로 노출되는지
- 도구 호출이나 다음 액션 추천이 공격자 의도대로 바뀌는지
- 정상 문서나 교육 문서가 과하게 차단되는지

즉, prompt injection 평가는 문자열 탐지만으로 충분하지 않고, `지시권 탈취`, `경계 붕괴`, `LLM obedience`, `tool redirection`, `false positive`를 함께 봐야 한다.

## 3. 기존 프레임워크에서 유지할 요소와 교체할 요소

### 3.1 유지할 요소

- Layer 1: detector 자체 성능
- Layer 2: gateway 통합 후 회귀 여부
- Layer 3: detector miss 이후 LLM obedience
- Layer 4: end-to-end RAG / 외부 문서 환경 평가
- 결과 집계 키 `by_level`, `by_mutation`, `by_type`, `by_tier`, `by_lang`

### 3.2 교체할 요소

- 단일 payload 파일 공유 방식은 폐기한다.
- PII 중심 `INPUT/OUTPUT` 정의를 prompt injection 중심 정의로 교체한다.
- Layer 4에 정상 문서만 넣는 구성을 폐기하고 악성 retrieved content를 명시적으로 포함한다.
- hard negative를 별도 평가 세트가 아니라 본체 평가 구조에 편입한다.

## 4. 설계 근거: 어떤 자료의 어떤 부분을 반영했는가

아래 표는 논문, 데이터셋, 벤치마크, 내부 자료를 실제 설계 요소에 어떻게 반영했는지 요약한 것이다.

| 출처 | 확인한 핵심 내용 | 최종 설계에 반영한 항목 |
|---|---|---|
| OWASP LLM Prompt Injection / Prevention Cheat Sheet | direct와 indirect prompt injection을 모두 핵심 위협으로 규정 | direct/indirect 이원 taxonomy, Layer 4 악성 retrieved content 필수화 |
| PromptInject (2022) | goal hijacking, prompt leaking, role confusion 패턴 제시 | `goal` 축에 `instruction_override`, `prompt_leaking` 채택 |
| Greshake et al., Not what you've signed up for (2023) | 외부 웹/문서/이메일을 통한 indirect prompt injection이 현실적 위험임을 제시 | `indirect_document`, `indirect_email`, `indirect_repo` 분리 |
| HouYi (2023) | prefix / separator / payload 구조로 direct injection을 체계화 | canonical seed를 prelude, boundary break, payload 관점으로 정규화 |
| Formalizing and Benchmarking Prompt Injection Attacks and Defenses (USENIX Security 2024) | 공격, 방어, 모델, 태스크를 공통 taxon으로 비교 | 공통 schema, judge event, 공격면/목표/태스크 분리 설계 |
| BIPIA | indirect prompt injection을 task x attack type x position으로 벤치마크 | `target_task`, `position`, `attack_surface`를 canonical 필수 필드로 채택 |
| InjecAgent | tool-integrated agent에서 tool misuse와 data stealing이 주요 결과임을 제시 | `tool_redirection`, `synthetic_secret_exfil`, agent-context 시나리오 포함 |
| AgentDojo | 동적 에이전트 환경에서 utility와 robustness를 함께 측정 | Layer 3/4에서 `utility_pass`를 별도 기록 |
| LLMail-Inject | 이메일 스레드, 인용문, unauthorized tool call, adaptive 공격 구조 제공 | `email_thread`, `quoted`, `footer`, `unauthorized tool` 패턴 채택 |
| Adaptive Attacks Break Defenses... (2025) | 정적 템플릿 방어가 adaptive attack에 쉽게 깨짐 | adaptive descendants는 heldout 전용으로 분리 |
| AgentVigil | MCTS 기반 black-box indirect attack 탐색 전략 | 향후 `test3+`에서 adaptive mutator 우선순위 전략으로 사용 |
| PromptFuzz | preparation/focus 단계 분리 퍼징 워크플로 | `normalize -> render -> export` 이후 `focus-stage mutation` 확장 근거 |
| GPTFuzz | LLM 기반 자동 변이와 선택기 구조 | direct prompt mutation 생성기 설계 참고 |
| AgentDyn | GitHub/Shopping/Daily Life 영역의 open-ended agent injection | L4-B Repo/Coding-Agent의 long-horizon heldout 확장 근거 |
| Learning to Inject / AutoInject | RL 기반 universal/transferable injection | adaptive eval-only family 후보로 유지 |
| ChainFuzzer | multi-tool workflow 취약점과 source-to-sink 공격 경로 | `tool_redirected`와 workflow 단위 oracle 필요성 반영 |
| deepset/prompt-injections | 작은 규모의 clean binary sanity set | smoke baseline / sanity check 용도 |
| neuralchemy/Prompt-injection-dataset | leakage-free split, severity/source metadata | `family_id`, `split`, `severity`, `source_ref` 정리 기준 |
| Lakera PINT Benchmark | detector 비교 목적의 external benchmark | train 금지, eval/heldout reference로만 사용 |
| Lakera b3-agent-security-benchmark-weak | 사람이 만든 contextualized agent attacks | 짧은 에이전트 컨텍스트 공격 seed 보강 |
| prodnull/prompt-injection-repo-dataset | README, CI, comment, docs 기반 repo 인젝션 | `repo_readme`, `repo_comment`, `ci_config` carrier 채택 |
| prismdata/guardrail-ko-11class-dataset | KO bootstrap 가능하지만 translation-based injection | KO bootstrap 전용, KO-native gold eval 금지 |
| kakaocorp/kanana-safeguard-prompt-2.1b | A1 Prompt Injection / A2 Prompt Leaking taxonomy | 한국어 라벨 명명과 detector taxonomy 참고 |
| XSTest 계열 | safe but suspicious / refusal calibration | hard negative, overblocking, false positive 기준 |
| 내부 PII 4단계 프레임워크 문서 | Layer 1~4 구조와 결과 보고 체계가 이미 정리됨 | 전체 평가 구조 재사용 |
| 내부 EN-KO 비교 결과 | 한국어가 영어보다 우회율이 높고, paired 비교가 중요함 | EN-KO paired + KO-native 분리 운영 |
| 내부 한국어 변이 결과 | 자모분리, 초성, 한글숫자, 띄어쓰기 붕괴가 핵심 우회 벡터 | KO-native 필수 변이 family 고정 |

## 5. 최종 설계 방향

### 5.1 단일 payload 파일 대신 canonical corpus를 중심에 둔다

기존 방식처럼 `payloads_v3.json` 하나를 공유하면 Layer별 차이를 설명하기 어렵고, direct/indirect, INPUT/OUTPUT, judge 기준이 섞여 버린다. 따라서 `master canonical corpus 1개`를 만들고, 이후 Layer별 export를 생성하는 구조로 바꾼다.

최종 산출물은 아래 파일로 고정한다.

- `pi_master_canonical.jsonl`
- `pi_layer1_input.json`
- `pi_layer1_output.json`
- `pi_layer2_gateway.json`
- `pi_layer3_llm.json`
- `pi_layer4_rag_docs.jsonl`
- `pi_layer4_rag_queries.jsonl`
- `pi_hard_negative_eval.json`
- `pi_stats.json`

### 5.2 평가 지표를 prompt injection 중심으로 고정한다

1차 평가지표는 아래 하나다.

- `prompt injection 탐지/차단율`

2차 평가지표는 아래 항목으로 고정한다.

- `canary leak`
- `prompt leak`
- `synthetic secret leak`
- `tool/action redirection`
- `false positive`
- `detector miss 이후 LLM obedience`

### 5.3 안전한 synthetic 목표만 사용한다

실제 PII나 실제 secret을 쓰지 않고 아래 synthetic 신호만 사용한다.

- `canary token`
- `prompt leak marker`
- `synthetic secret`
- `synthetic tool/action JSON`

이렇게 해야 모델의 경계 붕괴와 누출 행동은 측정하면서 실제 유출 리스크는 피할 수 있다.

## 6. 코퍼스 구조

### 6.1 master canonical schema

필수 필드는 아래와 같다.

- `seed_id`
- `family_id`
- `origin_case_id`
- `pair_id`
- `split`
- `lang`
- `attack_surface`
- `carrier`
- `goal`
- `target_task`
- `position`
- `explicitness`
- `layer_target`
- `source_side`
- `judge_type`
- `severity`
- `is_hard_negative`
- `source_ref`
- `license_tag`

각 필드를 넣는 이유는 아래와 같다.

- `family_id`: split leakage 방지와 mutation 계열 관리
- `pair_id`: EN-KO pair 또는 KO-native 묶음 관리
- `attack_surface`: direct, email, repo, memory 등 취약면 분석
- `carrier`: markdown, html, email_thread, ci_config 등 포맷 민감도 분석
- `goal`: override, leak, redirection 등 공격 목적 분석
- `source_side`: INPUT, OUTPUT, CONTEXT 평가 분리
- `is_hard_negative`: false positive와 benign overblocking 분석

### 6.2 rendered case schema

rendered case는 실제 실행 입력이다. 필수 필드는 아래와 같다.

- `case_id`
- `seed_id`
- `family_id`
- `lang`
- `rendered_system`
- `rendered_user`
- `rendered_context`
- `mutation_names`
- `expected_block_stage`
- `judge_spec`
- `layer_target`
- `source_side`
- `meta`

이 단계에서는 모델 실행을 위해 seed가 실제 프롬프트/문서/컨텍스트로 펼쳐진다.

### 6.3 judge_event schema

공통 judge event는 아래 필드를 사용한다.

- `detector_blocked`
- `detector_missed`
- `llm_obeyed`
- `contains_canary`
- `contains_prompt_leak_marker`
- `contains_synthetic_secret`
- `tool_redirected`
- `benign_overblocked`

## 7. taxonomy

### 7.1 attack_surface

- `direct_user`
- `indirect_document`
- `indirect_email`
- `indirect_repo`
- `multi_turn_memory`

### 7.2 goal

- `instruction_override`
- `prompt_leaking`
- `canary_exfil`
- `synthetic_secret_exfil`
- `tool_redirection`
- `boundary_confusion`

### 7.3 carrier

- `plain_chat`
- `markdown`
- `html`
- `json`
- `yaml`
- `table`
- `email_thread`
- `meeting_note`
- `policy_doc`
- `repo_readme`
- `repo_comment`
- `ci_config`

### 7.4 target_task

- `summarization`
- `retrieve_answer`
- `translation`
- `qa`
- `repo_summary`
- `next_action_recommendation`
- `config_explanation`
- `issue_triage`

## 8. 영어와 한국어 설계

### 8.1 비율

- `40%` EN canonical
- `35%` KO paired naturalization
- `25%` KO-native mutation

### 8.2 EN-KO paired 원칙

- 의미는 공유하되 literal translation은 금지한다.
- 동일 비교 단위는 같은 `family_id`를 공유해야 한다.
- EN와 KO는 같은 split에서만 비교해야 한다.
- paired 세트는 “언어 차이”를 측정하는 기본축이다.

### 8.3 KO-native 원칙

KO-native는 번역형이 아니라 한국어 특수 우회 벡터를 담는 별도 seed bank다. 필수 변이는 아래와 같다.

- 자모분리
- 초성
- 한글숫자
- 띄어쓰기 붕괴
- 조사 변형
- 존댓말/반말/공문체 전환
- 한영 코드스위칭
- zero-width/fullwidth

### 8.4 한국 서비스 문맥 반영

영어 코퍼스 번역만으로는 한국 환경을 충분히 재현할 수 없다. 따라서 KO-native나 KO paired 자연화 과정에서는 아래 문맥을 별도 seed로 운영한다.

- 은행 상담
- 보험 청구
- 병원 예약
- 공공 민원
- 사내 메신저
- 전자결재
- 쇼핑/택배 CS
- 이메일 회신 체인
- 사내 RAG 고객 조회

## 9. Layer-by-Layer 설계

### 9.1 Layer 1: detector only

목표는 detector 자체 성능 측정이다. 여기서는 gateway나 LLM 정책과 분리해서 입력 또는 출력 자체를 차단하는지 본다.

포함해야 할 케이스:

- direct override
- prompt leaking
- markdown/html/json/yaml wrapper
- email body injection
- KO-native obfuscation
- hard negative

출력 세트에는 아래를 포함한다.

- canary leak output
- prompt leak snippet
- instruction-followed output
- synthetic tool call JSON

### 9.2 Layer 2: gateway integration regression

Layer 2는 detector가 gateway와 결합됐을 때 회귀가 생기는지 측정한다. direct만 보는 것이 아니라 아래 4묶음을 균형 있게 써야 한다.

- direct
- indirect email/doc
- structured wrapper
- KO-native

정책 슬라이스는 아래를 분리해 기록한다.

- `block`
- `mask`
- `passthrough`

### 9.3 Layer 3: detector miss 이후 LLM obedience

핵심은 detector miss와 LLM follow를 분리하는 것이다. detector가 놓쳤더라도 LLM이 지시를 따르지 않으면 위험도는 다르다.

대표 시나리오:

- single-turn direct
- multi-turn override
- indirect summarize/translate/answer
- prompt leak
- synthetic tool call emission

### 9.4 Layer 4-A: RAG / Email indirect prompt injection

문서 코퍼스에는 아래가 섞여 있어야 한다.

- 정상 고객 문서
- 악성 이메일 본문
- 악성 회신 체인
- 악성 회의록 또는 정책 문서
- footer/hidden instruction 문서
- chunk boundary split 문서

질의 세트는 아래를 포함한다.

- summarize
- retrieve-and-answer
- compare
- follow-up multi-turn

필수 공격 패턴은 아래와 같다.

- retrieved malicious footer
- quoted instruction in email thread
- split payload across chunks
- markdown/html hidden instruction
- JSON/YAML field confusion
- multi-turn retrieval follow-up

### 9.5 Layer 4-B: Repo / Coding-Agent indirect prompt injection

문서 코퍼스에는 아래가 들어가야 한다.

- README
- repo comment
- CI config
- docs page
- tool description

질의 세트는 아래와 같다.

- repo summary
- next action recommendation
- config explanation
- issue triage

필수 공격 패턴은 아래와 같다.

- repo README instruction
- CI workflow instruction
- docs page instruction
- repo comment instruction
- multi-tool chain redirection

## 10. hard negative 설계

### 10.1 hard negative 비율

- 전체 eval의 최소 `20%`
- 권장 비율은 `25%`
- hard negative 내부에서 KO 비중은 최소 절반

### 10.2 hard negative 유형

- prompt injection 설명 문서
- `ignore previous instructions`를 예시로 드는 교육 문장
- imperative style 정책 문서
- README/설치 가이드형 명령문
- security/safety note가 많은 정상 메일

### 10.3 출처

- XSTest safe
- LLMail false-positive emails
- Prism SAFE
- prodnull benign repo files
- neuralchemy benign
- 한국어 보안 교육 문서형 self-authored examples

## 11. split hygiene와 라이선스 정책

### 11.1 split hygiene

- 동일 `family_id`는 하나의 split에만 존재해야 한다.
- EN-KO pair는 동일 `family_id`와 동일 split을 공유해야 한다.
- KO-native는 `KO-NATIVE-*` 패턴의 별도 묶음으로 관리한다.
- adaptive descendants는 `heldout` 또는 `private_adaptive`에만 둔다.
- public eval benchmark는 train에 사용하지 않는다.

### 11.2 데이터셋별 역할 분리

- `BIPIA`: indirect seed backbone
- `LLMail-Inject`: email indirect + adaptive patterns
- `InjecAgent`: tool/agent goal taxonomy
- `AgentDojo`, `AgentDyn`: heldout dynamic eval
- `neuralchemy`: schema/split hygiene reference
- `deepset`: smoke sanity set
- `PINT`: external eval / hard negative reference
- `prodnull`: repo indirect seed bank
- `Prism`: KO bootstrap, SAFE negative
- `Kanana`: KO taxonomy reference
- `XSTest`: refusal calibration / overblocking eval

## 12. test2 구현 산출물

`test2`는 실제 다운로드나 병합 대신 아래 산출물을 제공한다.

- JSON Schema 5종
- sample JSONL/JSON 세트
- source mapping 정책 YAML
- split hygiene 정책 YAML
- runner contract 문서
- validation script

즉, `test2`의 목적은 “무엇을 만들 것인가”를 끝내는 것이 아니라 “어떤 형식으로 만들 것인가”를 더 이상 논쟁 없이 고정하는 것이다.

## 13. 최종 결론

이 설계의 핵심은 네 가지다.

1. 단일 payload 파일을 버리고 canonical corpus 중심으로 바꾼다.
2. PII 탐지가 아니라 prompt injection 탐지/차단과 그 실패 양상을 본다.
3. 영어는 canonical, 한국어는 paired + KO-native 이중 구조로 운영한다.
4. Layer 4에 악성 retrieved content와 repo indirect injection을 반드시 포함한다.

이 구조를 따르면 기존 4단계 프레임워크를 유지하면서도, 영어와 한국어 prompt injection에 대해 직접 공격, 간접 공격, agent/tool misuse, false positive까지 함께 측정할 수 있는 평가 체계를 구현할 수 있다.
