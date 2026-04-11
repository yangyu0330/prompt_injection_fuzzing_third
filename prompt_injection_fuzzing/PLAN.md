# 영어·한국어 Prompt Injection Fuzzer 설계 계획서

## Summary
- 기존 PII 검증 틀인 [ccit2번4단계_검증_프레임워크_팀공유.md](C:\Users\andyw\OneDrive - 중부대학교\바탕 화면\2번째CCIT자료\ccit2번4단계_검증_프레임워크_팀공유.md), [Phase1_종합분석_한국어vs영어_비교.docx](C:\Users\andyw\OneDrive - 중부대학교\바탕 화면\2번째CCIT자료\Phase1_종합분석_한국어vs영어_비교.docx), [Layer1_3자비교_종합보고서.docx](C:\Users\andyw\OneDrive - 중부대학교\바탕 화면\2번째CCIT자료\Layer1_3자비교_종합보고서.docx), [해외·한국어 프롬프트 인젝션 퍼징 한국어 고품질 퍼지 케이스 설계 보고서.md](C:\Users\andyw\Downloads\해외·한국어 프롬프트 인젝션 퍼징 한국어 고품질 퍼지 케이스 설계 보고서.md)를 재사용하되, PII payload는 버리고 `무해 canary + synthetic secret + unauthorized tool-call schema`로 교체한다.
- 퍼저는 “문장 모음”이 아니라 `attack_surface × goal × carrier/context × mutation × language × layer` 곱집합으로 설계한다. 코퍼스는 `public-train`, `external-heldout`, `private-adaptive`, `benign-hard-negative` 4개 풀로 분리하고 절대 섞지 않는다.
- 언어 비교는 동일 의미의 EN-KO pair를 기준선으로 두고, 한국어는 별도로 `KO-native` 층을 운용한다. 이 구조는 내부 결과(한국어 이름 100% 유출, Bedrock 한국어 32.1% vs 영어 0.6%, L4 언어학 변형 최대 취약점) 때문에 필수다.

## 근거와 활용 매핑
| 출처 | 계획에 반영할 부분 |
|---|---|
| [OWASP LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) + [OWASP Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) | direct/indirect, tool misuse, exfiltration, multimodal, least privilege/HITL/trust-boundary를 전체 taxonomy와 안전 운영 원칙으로 사용 |
| [PROMPTINJECT 2022](https://arxiv.org/pdf/2211.09527) | `goal hijacking`/`prompt leaking`, `private value`, delimiter sensitivity를 `goal` 축, canary oracle, leak-oracle로 사용 |
| [HouYi / Prompt Injection attack against LLM-integrated Applications 2023](https://arxiv.org/abs/2306.05499) | `pre-constructed prompt + context partition + payload`를 seed IR의 표준 템플릿으로 사용 |
| [Not what you've signed up for 2023](https://arxiv.org/abs/2302.12173) | indirect PI의 원격 exploit, data/instruction blur, API/tool control 위험을 L4 RAG·email·repo 위협모델로 사용 |
| [Formalizing and Benchmarking Prompt Injection Attacks and Defenses 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-yupei) | 5 attacks/10 defenses/7 tasks 프레임을 mutation family와 분석 축(`which attack breaks which defense`)으로 사용 |
| [BIPIA 논문](https://arxiv.org/abs/2312.14197) + [BIPIA repo](https://github.com/microsoft/BIPIA) | 5 tasks(Web QA, Email QA, Table QA, Summarization, Code QA)와 `task × attack type × attack position`을 indirect seed backbone으로 사용 |
| [InjecAgent 2024](https://arxiv.org/abs/2403.02691) + [repo](https://github.com/uiuc-kang-lab/InjecAgent) | 1,054 cases, 17 user tools, 62 attacker tools, `direct harm vs private-data exfiltration`을 agent/tool goal taxonomy로 사용 |
| [Adaptive Attacks Break Defenses... 2025](https://aclanthology.org/2025.findings-naacl.395/) | 8개 defense 모두 adaptive 우회, ASR 50%+ 결과를 근거로 `held-out adaptive set`을 별도 운영 |
| [LLMail-Inject 2025 논문](https://arxiv.org/abs/2506.09956) + [HF dataset](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) | 208,095 unique submissions / HF 461,640 rows, email carrier, unauthorized `send_email` schema를 email-agent slice와 tool-call oracle로 사용 |
| [AgentVigil arXiv:2505.05849, 2025-05-09 제출](https://arxiv.org/abs/2505.05849) | MCTS seed selection, black-box adaptive search, AgentDojo/VWA-adv 71%/70%를 adaptive mutator prioritizer로 사용 |
| [AgentDyn 2026](https://arxiv.org/abs/2602.03117) | 60 open-ended tasks, 560 cases, Shopping/GitHub/Daily Life를 dynamic held-out eval과 GitHub/coding context로 사용 |
| [ChainFuzzer 2026](https://arxiv.org/html/2603.12614) | 365 vulnerabilities across 19/20 apps, 82.74% multi-tool을 L4 multi-tool chain, source→sink label, sink oracle에 사용 |
| [PromptFuzz 2024 repo](https://github.com/sherdencooper/PromptFuzz) | preparation/focus 2-stage workflow를 prompt-injection용 focus-stage mutation pipeline으로만 사용 |
| [GPTFuzz repo](https://github.com/sherdencooper/GPTFuzz) | mutator/seed-selector abstraction만 사용; 콘텐츠는 jailbreak 편향이라 직접 학습 코퍼스로는 쓰지 않음 |
| [neuralchemy dataset](https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset) | leakage-free split, category/severity/source/group split을 detector bootstrap 및 quality gate schema로 사용 |
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | 662-row lightweight sanity set을 smoke test와 분류기 초기 sanity check로 사용 |
| [PINT benchmark](https://github.com/lakeraai/pint-benchmark) | 4,314 inputs, multilingual, `hard_negatives` 카테고리를 held-out FPR/over-defense 평가셋으로만 사용 |
| [prodnull repo dataset](https://huggingface.co/datasets/prodnull/prompt-injection-repo-dataset) | 5,671 repo-file samples, 24 categories, code/config/README/CI-CD carrier를 coding-agent indirect slice로 사용 |
| [Kanana Safeguard-Prompt](https://huggingface.co/kakaocorp/kanana-safeguard-prompt-2.1b) | `A1 Prompt Injection / A2 Prompt Leaking`, 한국어·영어 최적화, false positive 최소화 원칙을 KO taxonomy와 detector track에 사용 |
| [PrismData guardrail-ko-11class](https://huggingface.co/datasets/prismdata/guardrail-ko-11class-dataset) | 324k rows 중 train `INJECTION 61,836`을 번역형 bootstrap만으로 사용하고 KO-native 근거로는 쓰지 않음 |
| [Korean Guardrail Dataset repo](https://github.com/skan0779/korean-guardrail-dataset) + [RICoTA 2025](https://arxiv.org/pdf/2501.17715) | 한국어 hard negative, 한국어 정상 채팅/문서 캐리어, Korean-only evaluation catalog로 사용 |
| 내부 문서 [ccit2번4단계_검증_프레임워크_팀공유.md](C:\Users\andyw\OneDrive - 중부대학교\바탕 화면\2번째CCIT자료\ccit2번4단계_검증_프레임워크_팀공유.md), [Phase1_종합분석_한국어vs영어_비교.docx](C:\Users\andyw\OneDrive - 중부대학교\바탕 화면\2번째CCIT자료\Phase1_종합분석_한국어vs영어_비교.docx), [Layer1_3자비교_종합보고서.docx](C:\Users\andyw\OneDrive - 중부대학교\바탕 화면\2번째CCIT자료\Layer1_3자비교_종합보고서.docx) | Layer 1~4 평가 구조, Gateway 통합 약화 분석, 3-engine complementarity, `L4 언어학 변형` 우선순위, EN-KO 보안 격차 측정 프레임을 그대로 재사용 |

## 핵심 설계
- 코퍼스는 4개 풀로 고정한다: `Seed/Public-Train`, `External-Heldout`, `Private-Adaptive`, `Benign-Hard-Negative`.
- `Seed/Public-Train` 영어는 기본 2,000 seed로 시작한다: 40% public benchmark seed(BIPIA/InjecAgent/LLMail-Inject/AgentDojo), 30% format-carrier mutation, 20% adaptive search seed(AgentVigil/PromptFuzz-style), 10% benign negative.
- 한국어는 3층으로 고정한다: `EN-KO paired 1,000`, `KO-native 1,500`, `KO benign hard negative 700`. KO 공격 케이스 내부 비율은 35% 번역·현지화, 45% KO-native mutation, 20% 한국 서비스 문맥(은행, 보험, 병원, 공공민원, 쇼핑 CS, 사내 메신저, 전자결재, 이메일, 고객조회 RAG)으로 둔다.
- 모든 case는 단일 IR로 정규화한다. 필수 필드는 `case_id`, `pair_id`, `language`, `attack_surface`, `attack_type`, `goal`, `carrier_type`, `attack_position`, `format_wrapper`, `obfuscation_family`, `linguistic_level`, `turn_count`, `tool_count`, `expected_success_stage`, `is_benign`, `source_trace`, `license_tag`, `oracle_type`, `layer_targets`.
- 결과 스키마는 `blocked_input`, `blocked_context`, `blocked_output`, `canary_emitted`, `prompt_leaked`, `tool_call_attempted`, `secret_exfil_attempted`, `utility_pass`, `latency_ms`, `cost_usd`, `engine_id`, `layer_id`로 통일한다.
- 공격면은 `direct user prompt`, `retrieved doc/web`, `email thread`, `repo file`, `tool output/arguments`, `memory`, `multi-tool chain` 7개로 고정한다. `multimodal/OCR`은 확장 항목으로 분리한다.
- 목표 축은 `instruction override`, `prompt leaking`, `privacy/PII exfiltration`, `unauthorized tool use`, `output steering`, `workflow escalation` 6개로 고정한다.
- 영어 mutation family는 `authority impersonation`, `delimiter breaking`, `quoted/footer/metadata injection`, `format confusion(JSON/YAML/HTML/Markdown/CSV)`, `payload split/long-context dilution`, `email/repo carrier`, `adaptive search`, `benign suspicious text` 8개로 고정한다.
- 한국어 mutation family는 `존댓말↔반말`, `띄어쓰기 붕괴`, `조사 변형`, `자모분리`, `초성`, `한글숫자`, `한자/로마자/영문 code-switch`, `zero-width/full-width/homoglyph`, `이모지/구두점 삽입`, `한국 서비스 문체` 10개로 고정한다. 내부 문서상 가장 취약했던 `자모·초성·L4 언어학 변형`을 우선순위 1로 둔다.
- 공격 성공은 실제 유해 콘텐츠가 아니라 `무해 canary`, `synthetic system prompt fragment`, `synthetic secret`, `unauthorized tool JSON`, `format contract violation`로만 판정한다. 실제 PII/실제 비밀값은 사용하지 않는다.

## Layer 1~4 적용 방식
- Layer 1은 detector/guardrail 단독 검증이다. `USER`, `RETRIEVED_CONTEXT`, `EMAIL`, `REPO`, `TOOL`, `MEMORY` 입력별 TPR/FPR을 본다. PII 때의 INPUT/OUTPUT 이원화는 prompt injection에 맞게 `INPUT/CONTEXT/OUTPUT` 삼원화로 바꾼다.
- Layer 2는 `Guardrail + Gateway` 검증이다. 동일 case를 gateway 필드 분리(`system`, `user`, `untrusted_context`, `tool_result`) 상태로 통과시켜 integration-loss, policy mismatch, mask/block/passthrough 차이를 측정한다.
- Layer 3은 `Guardrail + Gateway + LLM` 검증이다. direct override, indirect doc, multi-turn memory, quoted instruction, prompt leak, unauthorized tool suggestion을 EN/KO pair로 실행한다.
- Layer 4는 E2E 시뮬레이션이다. Track를 4개로 고정한다: `RAG-doc`(BIPIA/BadRAG/SafeRAG), `Email-agent`(LLMail-Inject), `Coding-agent/repo`(prodnull/AgentDyn GitHub), `Multi-tool workflow`(InjecAgent/ChainFuzzer). 한국어는 1~3 Track 전부 지원, 4번은 EN 우선 후 KO 캐리어를 추가한다.
- 평가 지표는 `ASR`, `FPR`, `Benign Utility`, `Refusal Calibration`, `Context Boundary Score`, `Tool Misuse Rate`, `EN-KO Gap`, `Layer Drop(L1→L4)`로 고정한다.
- 분석 보고서는 최소 `language × layer × surface × goal × mutation × engine` 피벗과 `source_trace` 기준 취약 seed 역추적을 포함한다.

## 테스트와 산출물
- 산출물은 5개로 고정한다: `source manifest`, `case schema`, `seed corpus`, `mutation library`, `layer runner + report spec`.
- 데이터 품질 테스트는 `group/source 단위 split leakage 0`, `모든 case에 source_trace/license/oracle 존재`, `EN-KO pair 의미 불일치 수동검수`, `KO-native가 번역형과 별도 태깅`, `hard negative 별도 라벨 보존`으로 둔다.
- 운영 acceptance는 `영어 2,000 base seed`, `한국어 3,200 base seed`, `5~8개 mutation family 확장`, `L1~L4 공통 결과 스키마`, `public eval과 private adaptive 분리`, `engine별 EN-KO gap 리포트 생성`이 모두 충족될 때로 둔다.
- 재현성 확보를 위해 모든 case는 `source_id`, `source version/date`, `transformation log`, `prompt template version`, `mutation version`, `runner version`을 남긴다.

## 가정과 명시적 결정
- 사용자 메모의 “Generic Black-Box Fuzzing… (2025, AgentFuzzer)”는 공식 arXiv 기준 2025년 5월 9일 제출된 [AgentVigil](https://arxiv.org/abs/2505.05849)로 정규화한다. 같은 메모의 [PromptFuzz](https://github.com/sherdencooper/PromptFuzz)와 [GPTFuzz](https://github.com/sherdencooper/GPTFuzz)는 서로 다른 별도 작업으로 취급한다.
- [prodnull/prompt-injection-repo-dataset](https://huggingface.co/datasets/prodnull/prompt-injection-repo-dataset)처럼 접근 동의가 필요한 자료는 라이선스/접근 승인 후 사용하고, 승인 전에는 schema만 반영하고 대체 seed는 BIPIA CodeQA + AgentDyn GitHub slice로 채운다.
- 2026 preprint 계열(AgentDyn, ChainFuzzer)은 `held-out/dynamic extension`으로 쓰고, MVP taxonomy의 anchor는 OWASP, PROMPTINJECT, HouYi, BIPIA, Formalizing, InjecAgent, LLMail-Inject, AgentVigil로 고정한다.
- PII 퍼징 자료는 “평가 구조와 한국어 취약점 우선순위”만 재사용하고, prompt injection용 실제 payload는 전부 새 IR와 synthetic canary 방식으로 다시 만든다.
