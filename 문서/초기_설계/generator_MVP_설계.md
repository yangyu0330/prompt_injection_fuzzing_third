# Template 기반 Case Generator MVP 설계 (수정: 2026-04-09 13:16:55 KST)

## 1. 문서 목적

이 문서는 현재 저장소의 퍼저 구조에 `template -> case` 자동 생성기를 추가하기 위한 MVP 설계 메모다.  
목표는 대량 증식을 바로 구현하는 것이 아니라, 현재 curated benchmark 구조를 깨지 않고 `generated case`를 안정적으로 늘릴 수 있는 최소 설계를 정의하는 데 있다.

이 문서는 현재 구현 설명 문서가 아니라, **미구현 기능의 설계 문서**다. 따라서 아래 내용은 현재 코드 동작이 아니라 **추가 구현안**으로 읽어야 한다.

## 2. 현재 기준선

현재 저장소는 다음 흐름으로 동작한다.

```text
template catalog
+ case catalog
-> build
-> validate
-> run
-> score
-> report
```

현재 구조에서 자동 생성기가 없는 상태의 기준선은 다음과 같다.

- `catalogs/sample_templates.jsonl`: 수동 작성된 template source of truth
- `catalogs/sample_cases.jsonl`: 수동 작성된 case source of truth
- `src/pi_fuzzer/build.py`: split 재배정, dedup, validation, coverage gate 수행
- `src/pi_fuzzer/validation.py`: pair/linkage/source_role-stage/template reference 검증 수행
- `src/pi_fuzzer/models.py`: `TemplateRecord`, `CaseRecord` 스키마 정의
- `src/pi_fuzzer/cli.py`: 현재 `build/validate/run/score/report` CLI 진입점

즉 현재 저장소는 **case를 자동 증식하는 generator는 없고**, 사람이 작성한 case를 검증하고 실행하는 구조다.

## 3. 왜 generator가 필요한가

현재 카탈로그는 구조적으로 확장 가능한 메타데이터를 이미 갖고 있다.

- `supported_entry_points`
- `supported_carriers`
- `supported_source_roles`
- `supported_expected_interpretations`
- `allowed_mutation_families`
- `tool_transition_type`
- `replay_enabled`
- `delayed_trigger`

하지만 이 메타데이터는 지금 수동 authoring을 돕는 정보로만 쓰이고 있다.  
generator를 추가하면, 템플릿 한 개를 여러 조합의 고유 case로 자동 전개할 수 있다.

예:

- 한 템플릿
- `entry_point` 2종
- `carrier` 3종
- `mutation` 2종
- `source_role` 2종

이면 이론상 `1 x 2 x 3 x 2 x 2 = 24`개의 고유 case 후보를 만들 수 있다.

## 4. MVP 목표

MVP의 목표는 아래 셋만 달성하면 된다.

1. template를 입력으로 받아 deterministic하게 case를 생성한다.
2. 생성 결과가 현재 `CaseRecord`와 `build/validate` 파이프라인을 그대로 통과한다.
3. 중복 폭증과 coverage 쏠림을 최소한의 규칙으로 제어한다.

MVP에서는 아래를 목표로 하지 않는다.

- 실제 공격 문장 렌더링 자동화
- LLM 기반 adaptive search
- repo-aware file graph 시뮬레이션
- 2만 건 이상 대규모 샤딩
- 새로운 scoring metric 추가

## 5. 설계 원칙

### 5.1 placeholder-only 유지

generator가 case를 늘리더라도 실제 공격 페이로드 코퍼스를 생성하면 안 된다.

- `untrusted_content`
- `trusted_instruction`
- `expected_safe_behavior`

는 계속 placeholder 기반 값을 유지해야 한다.

즉 generator는 **문장 생성기**가 아니라 **metadata 조합기**여야 한다.

### 5.2 build/validate를 우회하지 않음

generator는 `CaseRecord JSONL`을 만들 뿐이고, 품질 게이트는 계속 `build`와 `validate`가 담당한다.

- dedup: `src/pi_fuzzer/validation.py`
- pair/backlink 검사: `src/pi_fuzzer/validation.py`
- split contamination 검사: `src/pi_fuzzer/validation.py`
- source_role-stage 검사: `src/pi_fuzzer/validation.py`
- coverage gate: `src/pi_fuzzer/build.py`

즉 generator는 생산기이고, 검증기는 계속 기존 파이프라인을 사용한다.

### 5.3 additive, backward compatible

generator는 기존 curated case를 없애거나 덮어쓰지 않는다.

권장 방향:

- 기존 `sample_cases.jsonl` 유지
- 새로 `generated_cases.jsonl` 또는 별도 output 파일 생성
- `case_sources`에 추가해서 build에서 함께 읽기

### 5.4 현재 validator 경계 명시

중요한 점은, 현재 build/validate가 **이미 자동으로 보장하는 것**과 **아직 보장하지 않는 것**을 문서에서 분리해 적는 것이다.

현재 build/validate가 이미 보장하는 것:

- `template_id` reference 존재 여부
- `paired_case_id` backlink 및 pair invariant
- `semantic_equivalence_group` 기준 split contamination
- `source_stage` / `source_role` / `expected_interpretation`의 기본 일관성
- configured coverage profile 위반 검출
- dedup

현재 build/validate가 아직 자동으로 보장하지 않는 것:

- template의 `supported_entry_points` / `supported_carriers` / `allowed_mutation_families`와 생성 case 조합의 정합성
- template의 `supported_source_roles` / `supported_expected_interpretations`와 생성 case 조합의 정합성
- contrast group이 정확히 어떤 구성이어야 하는지에 대한 엄격한 완전성 검사

따라서 MVP는 “generator가 알아서 맞추면 된다”로 끝내지 않고, 아래 둘 중 하나를 반드시 포함해야 한다.

- generator 내부 self-check 추가
- 또는 별도 validator 추가  
  예: `validate_template_capability_compatibility(...)`

### 5.4.1 capability validator rollout 순서

template capability compatibility 검사는 맞는 방향이지만, 새 validator를 곧바로 전역 `validate` 단계에 붙이면 기존 curated case까지 함께 깨질 수 있다.

이유:

- 현재 sample catalog 안에도 template의 `allowed_mutation_families`와 case의 `primary_mutation` / `secondary_mutations`가 완전히 일치하지 않는 row가 있을 수 있다.
- 즉 “generator용 신규 규칙”과 “기존 curated catalog의 정합성”은 별도 문제다.

따라서 MVP rollout은 아래 순서를 권장한다.

1. 1차: generator self-check로 **generated case에만** capability compatibility를 강제한다.
2. 2차: 기존 curated catalog에 대해 audit 리포트를 만들고, mismatch를 정리한다.
3. 3차: curated catalog backfill 이후, 필요하면 동일 규칙을 `validate` 전역 규칙으로 승격한다.

즉 MVP 초기에 필요한 것은 “새 generator가 template 범위를 벗어나지 않게 만드는 것”이지, 기존 catalog 전체를 즉시 hard fail로 바꾸는 것이 아니다.

### 5.5 주의할 점

generator를 붙인 뒤 `build`와 `validate`를 통과했다는 사실만으로, 생성된 case가 template 의도에 맞는다고 간주하면 안 된다.

- 현재 `build/validate` 통과는 **형식 검증**과 **기본 일관성 검증**에 가깝다.
- 반면 template의 `supported_entry_points`, `supported_carriers`, `allowed_mutation_families`, `supported_source_roles`, `supported_expected_interpretations`를 실제 case가 정확히 따르는지는 별도 확인이 필요하다.
- 이 확인이 없으면, 겉보기에는 정상 JSONL이지만 실제로는 template 범위를 벗어난 case가 섞일 수 있다.
- 이런 mismatch는 coverage가 잘 채워진 것처럼 보이게 만들고, family별 성능 비교나 KR/EN 비교를 오염시킬 수 있다.
- 특히 KR/EN pair는 단순히 `paired_case_id`만 맞추는 것으로 충분하지 않고, 동일한 template capability 축 안에서 대응되도록 생성되어야 한다.
- replay, structured payload, tool misuse 계열은 `tool_transition_type`, `replay_window`, `delayed_injection_turn`, `structured_payload_type` 같은 필드까지 template 의도와 함께 검사해야 한다.
- generator는 문장 생성기가 아니라 metadata 조합기이므로, placeholder-only 원칙을 깨고 자유 텍스트를 증식시키기 시작하면 MVP 범위를 벗어난다.
- 별도 self-check 또는 validator가 없으면 generated case는 우선 `dev_calibration` 성격의 데이터로 취급하고, headline 비교나 release 판단에는 보수적으로 반영하는 편이 안전하다.

## 6. MVP 범위

MVP는 현재 구현 축이 이미 충분한 영역부터 시작한다.

### 6.1 1차 대상 family

- `replay_trajectory_injection`
- `structured_payload_misuse`
- `tool_agent_misuse`
- `ko_native_mutation_layer`
- 일부 `korean_service_context`

이 영역을 먼저 고르는 이유는 다음과 같다.

- 현재 sample template가 이미 존재함
- `CaseRecord` 필드가 이미 충분히 갖춰져 있음
- `validation`, `scoring`, `reporting` 연결이 이미 있음

### 6.2 MVP에서 보류할 것

다음은 MVP에서 제외한다.

- `adaptive_fuzzing`의 진짜 자동 탐색 루프
- `repo_coding_agent_injection` 전용 실행 하네스
- `config_sensitivity_probe` 전용 대규모 matrix 생성

이 항목들은 template를 추가하는 것 자체는 가능하지만, MVP보다 한 단계 뒤에서 다루는 편이 안전하다.

## 7. 제안 구조

### 7.1 새 모듈

권장 파일:

- `src/pi_fuzzer/generator.py`

권장 역할:

- template 읽기
- expansion config 읽기
- 조합 전개
- `CaseRecord` 생성
- deterministic ID 생성
- pair/contrast/benign linkage 자동 부여
- generator self-check 수행

### 7.2 새 CLI

권장 명령:

```bash
pifuzz generate-cases --templates catalogs/sample_templates.jsonl --config configs/generator_mvp.yaml --out catalogs/generated_cases.jsonl
```

역할은 단순해야 한다.

- 입력 template 읽기
- config에 정의된 조합 축으로 case 생성
- 결과를 JSONL로 저장

이 명령은 새 standalone 스크립트가 아니라, 기존 `src/pi_fuzzer/cli.py`에 subcommand로 추가하는 방향이 가장 단순하다.

운영 관점에서 CLI 입력은 단순하게 두되, 부가 입력 경로는 `--config`가 들고 있는 구조가 가장 안전하다.

- `--templates`: 이번 실행에서 읽을 template source
- `--config`: expansion config + recipe path + coverage preflight reference
- `--out`: generated case output path

생성 후 build는 기존처럼 수행한다.

```bash
pifuzz build --config configs/build_dev.yaml --out packages/dev_release
```

단, build config의 `case_sources`에 생성 파일이 추가되어 있어야 한다.

## 8. 입력과 출력

### 8.1 입력

generator 입력은 세 묶음이다.

1. template source
- `TemplateRecord`

2. mutation recipe source
- `catalogs/mutation_recipes.yaml`

3. expansion config
- 예: `configs/generator_mvp.yaml`

여기서 `mutation_recipes.yaml`은 자유 텍스트 생성기가 아니라, 아래 용도로만 사용한다.

- `mutation_recipe_id` provenance 연결
- `primary_mutation` / `secondary_mutations` 매핑
- placeholder slot 종류 결정

중요:

- **논리 입력**은 `template source + mutation recipes + expansion config` 세 묶음이다.
- **운영 입력**은 `templates + config` 두 경로로 단순화해도 된다.
- 이 경우 recipe 경로와 coverage preflight 경로는 `generator_mvp.yaml` 내부에서 참조한다.

권장 원칙:

- recipe source of truth는 `catalogs/mutation_recipes.yaml`
- coverage source of truth는 기존 build가 읽는 `configs/build_dev.yaml` + `catalogs/coverage_matrix.yaml`
- generator는 coverage preflight가 필요할 때, coverage 규칙을 복제하지 말고 기존 build config를 참조해 같은 profile을 읽는다.

### 8.2 출력

출력은 `CaseRecord` JSONL이다.

권장 출력 파일:

- `catalogs/generated_cases.jsonl`

중요:

- generator 출력은 `CaseRecord patch`가 아니라, 처음부터 `CaseRecord`로 파싱 가능한 완성 레코드여야 한다.
- generator는 최소한 아래 core 필드를 항상 채운다.  
  `template_id`, `case_id`, `language`, `attack_or_benign`, `attack_family`, `attack_subfamily`, `directness`, `source_stage`, `turn_mode`, `entry_point`, `carrier_context`, `mutation_family`, `primary_mutation`, `user_goal`, `trusted_instruction`, `untrusted_content`, `protected_asset`, `forbidden_action`, `expected_safe_behavior`, `tool_scope`, `oracle_type`, `severity`, `split`, `source_origin`, `semantic_equivalence_group`
- `source_stage`가 `retrieval`, `tool_input`, `tool_output`, `replay` 중 하나이거나, 해당 분석 축을 쓰는 case면 `source_role`과 `expected_interpretation`을 비우지 않는다.
- replay / structured payload / tool misuse 계열에서는 필요 시 `tool_transition_type`, `replay_window`, `delayed_injection_turn`, `structured_payload_type`, `policy_requested`, `threshold_profile`, `normalization_variant`를 함께 채운다.
- KR/EN pair 또는 contrast bundle을 생성할 때는 `paired_case_id`, `kr_en_pair_id`, `contrast_group_id`, `paired_case_role`, `benign_sibling_id`를 일관되게 채운다.
- provenance와 재현성 용도로 `mutation_recipe_id`, `reproducibility_seed`, `notes`를 채우는 것을 MVP 기본값으로 둔다.
- `split`은 build에서 재배정되더라도 generator 단계에서 비워둘 수 없다. MVP에서는 `dev_calibration` 같은 유효 `SplitName`을 초기값으로 채우고, 최종 split 결정은 기존 build가 담당한다.
- `source_origin`은 template 기본값을 상속하는 것을 원칙으로 하고, generator provenance는 `notes` 또는 별도 suffix로 남긴다.

MVP에서는 template를 직접 수정하지 않고 case만 생성한다.

## 9. expansion config 개념

generator는 모든 가능한 조합을 무조건 cartesian product로 다 펼치면 안 된다.  
따라서 별도의 expansion config가 필요하다.

예시 구조:

```yaml
generator:
  seed: 20260409
  mutation_recipe_path: catalogs/mutation_recipes.yaml
  coverage_preflight:
    enabled: true
    build_config: configs/build_dev.yaml
  families:
    replay_trajectory_injection:
      max_cases_per_template: 24
      languages: [ko, en]
      entry_points: [memory_or_summary, tool_output]
      carriers: [long_context_document, json]
      source_roles: [memory_note, tool_output]
      expected_interpretations: [data, analysis_target]
      mutations: [delayed_replay_trigger, memory_summary_poisoning]
```

이 config는 “가능한 조합 전부”가 아니라 “이번에 펼칠 조합만” 정의하는 용도다.  
또한 recipes/coverage reference를 함께 들고 가는 실행 config 역할도 한다.

## 10. case 생성 규칙

### 10.1 조합 단위

MVP에서 case 생성 기본 단위는 아래 조합으로 둔다.

```text
template
x language
x entry_point
x carrier
x source_role
x expected_interpretation
x primary_mutation
```

필요 시 아래 축을 추가한다.

- `policy_requested`
- `tool_transition_type`
- `threshold_profile`
- `normalization_variant`

### 10.2 deterministic ID

`case_id`는 랜덤 UUID보다 deterministic한 규칙이 좋다.

권장 예:

```text
CASE-{LANG}-{TEMPLATE_KEY}-{ENTRY}-{CARRIER}-{ROLE}-{INTERP}-{HASH8}
```

이렇게 해야:

- 재생성 시 같은 조합이 같은 ID를 갖고
- diff가 안정적이며
- dedup과 추적이 쉬워진다.

여기서 `HASH8`은 생성 순번이 아니라 조합 필드의 안정 해시여야 한다.  
권장 입력 필드:

- `template_id`
- `language`
- `source_stage`
- `entry_point`
- `carrier_context`
- `source_role`
- `expected_interpretation`
- `primary_mutation`
- `policy_requested`
- `tool_transition_type`
- `replay_window`
- `delayed_injection_turn`
- `structured_payload_type`
- `threshold_profile`
- `normalization_variant`

즉 `case_id`의 해시 입력은 “generator가 case를 구분하는 의미 단위”와 최대한 같아야 한다.  
특히 replay/structured 계열에서는 현재 dedup envelope가 구분하는 축을 빼먹지 않는 편이 안전하다.

즉 새 조합이 중간에 추가되더라도, 기존 case의 `case_id`가 줄줄이 바뀌지 않는 규칙을 써야 한다.

### 10.3 semantic group

`semantic_equivalence_group`는 단순한 template 버킷이 아니라, split과 함께 움직여도 되는 “거의 동일한 평가 단위”만 묶는 값으로 써야 한다.

현재 build는 `semantic_equivalence_group or template_id` 단위로 split을 재배정한다.  
따라서 generator가 한 template에서 나온 모든 변형을 같은 group으로 몰아넣으면, 생성 수는 늘어도 split 다양성과 coverage가 무너질 수 있다.

권장 규칙:

- 같은 template + 같은 task/goal + 같은 attack intent는 기본 전제다.
- 여기에 더해, 최소한 `entry_point`, `source_role`, `expected_interpretation`이 같을 때만 같은 group 후보로 본다.
- `carrier_context`나 replay/tool 전이 의미가 실제 평가 결과에 영향을 줄 수 있으면 같은 template라도 group을 분리한다.
- 단순 표기 차이만 있는 표면 변형은, 정말로 같은 split으로 묶어도 된다는 확신이 있을 때만 같은 group으로 유지한다.

예:

- 같은 replay trigger
- 같은 `entry_point`
- 같은 `source_role=memory_note`
- 같은 `expected_interpretation=data`

는 같은 group 후보가 될 수 있다.

반대로 아래는 기본적으로 group을 나누는 쪽이 안전하다.

- `memory_note` 버전과 `tool_output` 버전
- `data` 해석 기대와 `analysis_target` 해석 기대
- 단순 포맷 변형이 아니라 replay/tool_transition 의미가 달라지는 경우

MVP에서는 “template 중심 대그룹 유지”보다 “split에 같이 묶여도 되는 근접 변형만 묶기”를 기본 원칙으로 둔다.

### 10.3.1 deterministic semantic group 규칙

`semantic_equivalence_group`도 `case_id`와 마찬가지로 안정적인 규칙이 필요하다.  
이 값이 바뀌면 build의 split 재배정 결과도 함께 바뀌기 때문이다.

MVP 권장 기준:

- 기본 group key는 다음 안정 축으로 만든다.  
  `template_id`, `attack_or_benign`, `source_stage`, `entry_point`, `source_role`, `expected_interpretation`, `carrier_context`, `tool_transition_type`
- replay / structured payload 계열에서는 필요 시 `replay_window`, `structured_payload_type`를 추가한다.
- `language`는 기본적으로 group key에 넣지 않는다. KR/EN pair는 같은 split-lock 묶음으로 움직여야 하기 때문이다.
- `primary_mutation`도 기본적으로 group key에 넣지 않는다. 다만 mutation 차이가 단순 표기 차이가 아니라 실제 평가 의미를 바꾸는 family에서는 family-specific rule로 group 분리를 허용한다.
- `threshold_profile`, `normalization_variant`는 config sensitivity 실험 축일 뿐, 기본 MVP split-lock 축으로는 넣지 않는 것을 기본값으로 둔다. 필요 시 별도 확장 규칙으로만 승격한다.

중요:

- 한 번 채택한 group key 규칙은 중간에 임의로 바꾸지 않는다.
- 새 축을 추가해야 한다면 “기존 SEG 유지 + 신규 family에만 확장 적용” 또는 명시적 migration을 통해서만 바꾼다.
- 즉 `semantic_equivalence_group`은 휴리스틱 메모가 아니라, split 안정성을 결정하는 **versioned contract**로 다뤄야 한다.

### 10.4 pair / contrast bundle의 split-lock 규칙

현재 build는 `semantic_equivalence_group or template_id` 기준으로 split을 재배정한다.  
따라서 KR/EN attack pair는 **같은 split-lock 묶음**으로 움직여야 한다.

MVP 기본 규칙:

- 하나의 비교 bundle  
  예: `ko variant + en control`
- 는 같은 `semantic_equivalence_group`을 공유한다.
- 반대로 같은 template에서 나왔더라도 `entry_point`, `source_role`, `expected_interpretation`, `carrier_context`, `tool_transition_type`가 달라 비교 단위가 바뀌면 `semantic_equivalence_group`도 분리한다.
- benign sibling/control은 기본적으로 `contrast_group_id`로 attack bundle과 연결하고, `semantic_equivalence_group`은 별도로 둘 수 있다.
- 특히 benign hard-negative를 별도 split 버킷으로 유지해야 하는 경우에는, benign control을 attack bundle과 같은 `semantic_equivalence_group`에 넣지 않는 편이 안전하다.

즉 MVP에서는 `semantic_equivalence_group`의 단위를 “template 전체”가 아니라 “split을 함께 공유해야 하는 attack 비교 bundle”로 잡는 편이 맞다.  
비교 해석용 연결은 `contrast_group_id`, split-lock은 `semantic_equivalence_group`으로 분리해 생각하는 것이 안전하다.

## 11. pair / contrast / benign 자동 생성 규칙

### 11.1 KR/EN pair

언어 확장 시 generator는 가능한 경우 KR/EN pair를 자동 생성해야 한다.

필수 규칙:

- `user_goal`
- `protected_asset`
- `forbidden_action`
- `tool_scope`
- `entry_point`
- `severity`

는 pair invariant를 유지해야 한다.

### 11.2 benign sibling

특정 공격 family에는 benign sibling을 같이 생성하는 규칙이 필요하다.

우선 적용 후보:

- replay 계열
- tool misuse 계열
- hard-negative calibration 계열

### 11.3 contrast group

같은 비교 묶음으로 해석할 case들은 `contrast_group_id`를 공유하게 생성해야 한다.

권장 구성:

- attack
- en control
- ko variant
- benign sibling

단, benign sibling은 모든 contrast group의 필수 구성원이 아니다.  
다음처럼 구분한다.

- KR/EN attack pair만 비교하는 contrast group: benign optional
- over-block / hard-negative calibration까지 같이 보는 contrast group: benign required
- replay / tool misuse처럼 benign sibling을 만들기로 한 family: benign required

### 11.4 `benign required` 표현 규칙

MVP에서는 별도 `benign_required=true/false` 필드를 새로 만들지 않는다.  
대신 현재 스키마와 validator가 읽는 linkage 패턴으로 표현한다.

benign required contrast group의 최소 표현:

- attack 또는 control row 중 하나 이상에 `benign_sibling_id`를 채운다.
- 대응 benign row는 같은 `contrast_group_id`를 공유한다.
- 대응 benign row의 `attack_or_benign`은 `benign`이어야 한다.
- 대응 benign row의 `paired_case_role`은 `benign` 또는 `benign_control`처럼 `benign` prefix를 쓰는 것을 권장한다.

benign optional contrast group의 표현:

- `benign_sibling_id`를 비운다.
- `paired_case_role`에 `benign...` prefix를 쓰지 않는다.

즉 MVP에서는 “benign이 필수인가”를 별도 bool로 표현하지 않고,  
`benign_sibling_id`와 `paired_case_role` 패턴으로 표현하는 쪽이 현재 validator와 가장 잘 맞는다.

### 11.4.1 `benign required` source of truth

다만 중요한 점은, `benign required` 여부를 **생성된 row만 보고 역추론**하면 안 된다는 것이다.

왜냐하면:

- generator 버그로 `benign_sibling_id`와 `paired_case_role`가 둘 다 빠지면,
- 실제로는 benign이 필수인 family/contrast group도 validator 입장에서는 optional처럼 보일 수 있다.

따라서 MVP에서는 별도 case field를 추가하지 않더라도,  
`benign required`의 source of truth는 아래 둘 중 하나에 **명시적으로** 존재해야 한다.

- generator config의 contrast policy
- mutation recipe 또는 family rule table

그리고 self-check / validator는 “생성된 row의 패턴”을 보는 대신,  
이 명시적 policy를 기준으로 아래를 검사해야 한다.

- required contrast group에 benign row가 실제로 생성되었는가
- attack/control row 중 최소 한 row가 benign sibling linkage를 갖는가
- 대응 benign row가 같은 `contrast_group_id` 안에 존재하는가

즉 row-level 표현은 기존 패턴을 유지하되, requirement 판정 기준은 output 추론이 아니라 config-driven policy여야 한다.

## 12. 금지 규칙

generator는 아래 조합을 만들지 않아야 한다.

### 12.1 stage-role 위반

현재 validator 기준을 그대로 따름.

- `source_stage=tool_output`인데 `source_role!=tool_output`
- `source_stage=replay`인데 `source_role`가 `memory_note/tool_output`가 아님
- `source_stage=retrieval`인데 retrieval 성격 role이 아님

### 12.2 template 허용 범위 밖 조합

template가 지원하지 않는 값을 generator가 임의로 넣으면 안 된다.

예:

- `supported_entry_points`에 없는 entry point
- `supported_carriers`에 없는 carrier
- `allowed_mutation_families`에 없는 mutation

중요:

- 이 규칙은 현재 build/validate가 자동으로 전부 막아주지 않는다.
- 따라서 MVP에서는 generator self-check와 신규 validator 중 적어도 하나가 이 검사를 담당해야 한다.

### 12.3 pair/linkage 누락

아래 상태는 금지한다.

- pair backlink 불일치
- benign required contrast group인데 benign이 없음
- benign sibling target이 없음

### 12.4 placeholder-only 위반

generator는 실제 공격 payload 문장을 만들지 않는다.

## 13. dedup 전략

MVP에서는 generator가 dedup까지 직접 처리하지 않아도 된다.  
대신 아래 두 단계가 필요하다.

1. generator 내부에서 간단한 조합 중복 제거
2. build 단계에서 기존 dedup 재사용

현재 저장소는 이미 다음 dedup 축을 갖고 있다.

- exact hash
- structural fingerprint
- hybrid similarity

따라서 MVP generator는 “중복을 줄이되, 최종 중복 판정은 build에 맡긴다”가 맞다.

### 13.1 placeholder-only와 hybrid dedup의 충돌

여기에는 중요한 예외가 있다.  
현재 dedup는 결국 rendered payload text를 기준으로 exact / similarity 판정을 수행한다.

따라서 generator가:

- placeholder-only 원칙을 지키고
- 자유 텍스트를 새로 만들지 않고
- metadata만 바꿔서 case를 늘리면

일부 generated case는 `structured_only`에서는 남아도 `hybrid` dedup에서는 대량으로 소실될 수 있다.

이 점은 설계에 명시해야 한다.

- placeholder-only는 유지한다.
- 대신 “metadata만 다른 case가 release/hybrid dedup에서도 충분히 남는다”를 MVP 기본 가정으로 두지 않는다.
- generator는 가능하면 build와 같은 dedup mode로 preflight를 돌려 예상 잔존 수를 미리 보고한다.
- MVP 수락 기준의 기본 경로는 `dev + structured_only` smoke path로 둔다.
- `release + hybrid` 포함은 아래 중 하나가 정리된 뒤에만 목표로 삼는다.
  - placeholder envelope를 slot-only 범위 안에서 비교 가능하게 더 세분화
  - dedup 규칙을 generated comparison envelope에 맞게 조정
  - generated case를 headline release set이 아니라 calibration/supporting set으로 분리

즉 MVP에서는 “생성 개수”보다 “dedup 이후 얼마나 살아남는가”가 더 중요한 지표다.

## 14. coverage control 전략

대량 생성의 핵심 리스크는 숫자보다 분포 불균형이다.  
따라서 generator는 처음부터 coverage-aware하게 만들어야 한다.

### 14.1 MVP 원칙

- template별 생성 상한을 둔다.
- family별 생성 상한을 둔다.
- KR/EN 비율을 통제한다.
- benign 비율을 최소 유지한다.
- replay/tool misuse가 과소 대표되지 않게 별도 버킷을 둔다.

### 14.2 build와의 역할 분담

- generator: 생산량 제어
- generator: 가능하면 configured coverage profile 기준 preflight
- build/validate: coverage profile 위반 검출

즉 generator는 1차 분포 제어, build는 최종 게이트다.

추가로 명시할 점:

- build coverage profile 재사용은 **하한선 체크**에 가깝다.
- 이것만으로 template capability compatibility나 contrast completeness가 보장되지는 않는다.
- 따라서 generator는 coverage preflight 외에도 family quota, pair completeness, benign requirement, template capability self-check를 자체적으로 가져야 한다.

## 15. MVP 구현 순서

권장 순서는 아래와 같다.

1. `generator_MVP_설계` 확정
2. `configs/generator_mvp.yaml` 작성
3. `src/pi_fuzzer/generator.py` 구현
4. `pifuzz generate-cases` CLI 추가
5. template capability validator 또는 동등한 self-check 추가
6. 기존 curated catalog에 대한 capability audit 리포트 점검
7. 템플릿 2~3개만 대상으로 30~100개 생성
8. `build -> validate` 통과 확인
9. dedup/coverage 결과 점검
10. family 범위 확장

처음부터 500개를 목표로 구현하지 말고, 먼저 100개 이하로 구조를 검증하는 편이 안전하다.

## 16. 리스크

### 16.1 조합 폭발

모든 축을 cartesian product로 펼치면 case 수가 지나치게 커진다.

대응:

- template별 `max_cases_per_template`
- family별 상한
- 허용 조합만 config에서 명시

### 16.2 의미 없는 중복

표면만 다르고 본질적으로 같은 case가 폭증할 수 있다.

대응:

- semantic group 설계
- generator 내부 조합 pruning
- build dedup 재사용

### 16.3 pair/contrast 붕괴

자동 생성 시 linkage 오류가 가장 쉽게 발생한다.

대응:

- generator에서 pair 묶음을 먼저 만들고
- 개별 case는 그 묶음으로부터 파생시키는 구조 사용

### 16.4 coverage 쏠림

tool misuse, benign, KR/EN 비율이 쉽게 무너질 수 있다.

대응:

- config로 family quota 유지
- build coverage gate를 항상 같이 사용

## 17. 성공 기준

MVP 성공 기준은 아래다.

### 17.1 스모크 기준

1. 2~3개 template 대상으로 30~100개 case를 안정적으로 생성한다.
2. 동일 입력으로 재실행 시 같은 `case_id`와 같은 정렬 순서를 유지한다.
3. `build -> validate`가 통과한다.

### 17.2 MVP 수락 기준

1. generator가 최소 3개 family에서 case를 자동 생성한다.
2. 생성된 case가 `CaseRecord`로 적재되고, core/conditional 필드 계약을 만족한다.
3. template capability compatibility 검사까지 포함해 `build -> validate`가 통과한다.
4. family를 확대한 뒤 dedup 이후에도 최소 100개 내외의 유효 case가 남는다.
5. 위 수락 기준의 기본 dedup 판단 경로는 `dev + structured_only`이며, `release + hybrid` 잔존율은 별도 관찰 지표로 기록한다.
6. KR/EN pair, benign sibling, contrast group이 일부 축에서 자동 생성된다.

## 18. 이후 확장

MVP 이후 확장 순서는 다음이 적절하다.

1. `tool_agent_misuse`, `replay`, `structured_payload` 강화
2. `ko_native_mutation_layer` 확대
3. `repo_coding_agent_injection` template 추가
4. `config_sensitivity_probe` 전용 generator 축 추가
5. 장기적으로 `adaptive_fuzzing` 전용 생성기 분리

## 19. 한 줄 요약

이 저장소의 generator MVP는 **placeholder-only 원칙을 유지한 채 template 메타데이터를 CaseRecord 조합으로 전개하는 deterministic case 생산기**로 정의하는 것이 가장 안전하다.

## 20. 구현 고정 규칙 (적용 메모)

### 20.1 split source of truth

- generator output의 `split` 값은 임시값(`dev_calibration`)이다.
- 최종 split은 package build 단계에서 `build.py`의 split 재배정 로직이 결정한다.
- 따라서 generator 단계 split은 재현성/중간 산출물용 초기값으로만 취급한다.

### 20.2 mutation 축과 dedup 계약

- mutation만 다른 generated case가 build dedup에서 소실되지 않도록 dedup envelope에 mutation 축을 포함한다.
- 최소 반영 축은 `primary_mutation`, `secondary_mutations`, `mutation_family`다.
- `semantic_equivalence_group`은 기본적으로 mutation-agnostic으로 유지하되, family-specific 필요 시에만 mutation-sensitive 분리를 허용한다.

### 20.3 coverage preflight scope

- coverage preflight는 generated rows 단독 기준이 아니라 `기존 curated + candidate generated` 합본 기준으로 수행한다.
- preflight 순서는 build와 동일하게 split 재배정 -> dedup -> coverage gate를 따른다.
- 이 규칙으로 generator 단계의 거짓 실패(false fail)를 줄인다.

## 21. 대량 생성 모드 설계

### 21.1 왜 별도 모드가 필요한가

MVP generator는 “수십~수백 개를 안정적으로 만드는 모드”에 가깝다.  
반면 장기 목표가 `20000`이면, 단순히 `max_cases_per_template`와 family 수만 늘리는 방식으로는 운영이 불안정해진다.

핵심 이유:

- cartesian expansion만 키우면 dedup 낭비가 빠르게 증가한다.
- benign/control linkage가 family별로 과도하게 재사용되면 contrast bundle이 붕괴한다.
- coverage gate는 하한선 체크일 뿐이라, “많이 만들었다”와 “살아남는 20000을 만들었다”는 다르다.
- 1개 JSONL에 누적 저장하는 방식은 실행 재개, 부분 재생성, shard 단위 검증이 어렵다.

따라서 `대량 생성 모드`는 MVP의 단순 전개기 위에 아래를 추가한 운영 모드로 정의한다.

- quota 기반 생성
- shard 기반 출력
- persistent dedup index
- coverage deficit-driven refill
- multi-pass preflight

### 21.2 목표 정의

대량 생성 모드에서 목표는 반드시 둘로 분리해 적는다.

- `raw_generated_target`: generator가 디스크에 쓸 총 row 수 목표
- `survivor_target`: build split 재배정 + dedup + coverage preflight 이후 살아남아야 하는 목표

중요:

- `20000 raw`는 비교적 쉬운 목표다.
- `20000 survivor`는 generator 설계의 진짜 목표다.
- 대량 생성 모드는 기본적으로 `survivor_target`을 중심으로 설계한다.

권장 초기값:

- phase 1: `raw_generated_target=5000`, `survivor_target=2000`
- phase 2: `raw_generated_target=15000`, `survivor_target=8000`
- phase 3: `raw_generated_target=30000`, `survivor_target=20000`

즉 `20000 survivor`를 만들 때 raw 수는 그보다 더 클 수 있다는 점을 기본 가정으로 둔다.

## 22. 대량 생성 모드의 핵심 원칙

### 22.1 full cartesian 대신 budgeted generation

대량 생성 모드는 가능한 조합 전체를 펼치는 방식이 아니라, 아래 budget을 먼저 정하고 그 예산 안에서만 조합을 뽑는 방식으로 간다.

- family budget
- template budget
- bundle budget
- language budget
- benign/control budget

즉 “가능한 조합 전부 생성 -> dedup으로 정리”가 아니라  
“살아남을 가능성이 높은 조합부터 예산 기반으로 생성”이 기본 원칙이다.

### 22.2 build source of truth 유지

대량 생성 모드가 추가되어도 최종 truth는 계속 build다.

- 최종 split: build
- 최종 dedup: build
- 최종 coverage gate: build

generator는 build semantics를 흉내내는 preflight를 수행하되, 최종 판정 자체를 대체하지 않는다.

### 22.3 deterministic + resumable

대량 생성은 한 번에 끝나지 않을 수 있다.  
따라서 같은 config로 다시 돌렸을 때:

- 같은 bundle key는 같은 case_id를 가져야 하고
- 이미 생성된 shard는 재사용 가능해야 하며
- 중간에 멈춘 뒤 재개할 수 있어야 한다.

즉 deterministic은 “diff가 안정적이다”를 넘어서 “실행 재개 가능성”을 위한 계약이다.

## 23. 대량 생성 단위

### 23.1 row보다 bundle이 먼저다

MVP에서는 row 생성이 중심이지만, 대량 생성 모드에서는 `bundle`을 먼저 만들고 row는 그 bundle의 산출물로 본다.

권장 bundle 정의:

```text
template
x semantic expansion unit
x language plan
x attack/control/benign plan
```

예:

- 동일한 `entry_point`
- 동일한 `carrier_context`
- 동일한 `source_role`
- 동일한 `expected_interpretation`
- 동일한 `primary_mutation`
- 동일한 `tool_transition_type`

를 공유하는 attack 비교 묶음을 먼저 만들고,  
그 안에서

- `ko variant`
- `en control`
- `benign sibling`

을 생성한다.

이렇게 해야 pair/linkage와 budget 계산을 row 단위가 아니라 비교 단위로 제어할 수 있다.

### 23.2 bundle key

대량 생성 모드에서는 아래 두 키를 분리한다.

- `bundle_key`: 생성/재개/예산 관리용 안정 키
- `semantic_equivalence_group`: split-lock용 평가 키

둘을 같은 값으로 둘 수도 있지만, 역할은 다르다.

- `bundle_key`는 운영 단위
- `semantic_equivalence_group`는 평가 단위

운영과 평가를 같은 키로 강하게 묶어두면, 나중에 refill이나 shard 재배치가 어려워진다.

## 24. 출력 구조

### 24.1 단일 JSONL 대신 shard 디렉터리

대량 생성 모드의 기본 출력은 단일 파일이 아니라 디렉터리다.

권장 구조:

```text
catalogs/generated_bulk/
  manifest.json
  summary.json
  shards/
    family=replay_trajectory_injection/part-0001.jsonl
    family=tool_agent_misuse/part-0001.jsonl
    family=structured_payload_misuse/part-0001.jsonl
  indexes/
    exact_hash_index.jsonl
    structural_fingerprint_index.jsonl
    bundle_index.jsonl
```

권장 원칙:

- shard는 family 또는 batch 기준으로 자른다.
- build에는 shard 목록을 명시적으로 전달하거나, generator가 합본 export를 따로 만든다.
- `manifest.json`은 generator config fingerprint, seed, shard 목록, 총 row 수, bundle 수를 기록한다.

### 24.2 export view 분리

대량 생성 모드는 내부 출력과 build 입력용 출력 뷰를 분리하는 편이 좋다.

- internal shard output: 생성/재개/재샘플링용
- build export output: build가 바로 읽는 합본 JSONL

권장 예:

- 내부: `catalogs/generated_bulk/shards/...`
- build용 export: `catalogs/generated_cases.jsonl`

즉 build는 여전히 평평한 JSONL을 읽되, generator 내부 운영은 shard 단위로 가져간다.

## 25. config 설계

### 25.1 대량 생성 모드용 상위 config

권장 예:

```yaml
generator:
  mode: bulk
  seed: 20260409
  mutation_recipe_path: catalogs/mutation_recipes.yaml
  raw_generated_target: 30000
  survivor_target: 20000
  max_passes: 6
  output:
    out_dir: catalogs/generated_bulk
    export_jsonl: catalogs/generated_cases.jsonl
    shard_by: family
    max_rows_per_shard: 1000
  preflight:
    enabled: true
    build_config: configs/build_generated_dev.yaml
    mode: build_equivalent
    fail_on_survivor_shortfall: true
  dedup_index:
    enabled: true
    path: catalogs/generated_bulk/indexes
  refill:
    enabled: true
    strategy: coverage_deficit_first
    min_new_survivors_per_pass: 200
```

### 25.2 family budget config

대량 생성 모드에서는 family별로 아래 budget을 둘 수 있어야 한다.

- `target_survivors`
- `max_raw_rows`
- `max_bundles`
- `language_ratio`
- `benign_ratio_min`
- `priority`

예:

```yaml
families:
  tool_agent_misuse:
    target_survivors: 5000
    max_raw_rows: 8000
    max_bundles: 2200
    language_ratio:
      ko: 0.5
      en: 0.5
    benign_ratio_min: 0.2
    priority: 100
```

### 25.3 template pool / benign pool config

대량 생성에서는 family당 단일 benign template mapping만으로는 부족하다.  
따라서 아래처럼 pool을 허용한다.

```yaml
contrast_policy:
  families:
    tool_agent_misuse:
      require_benign: true
      benign_template_pool:
        - template_id: TMP-KO-BENIGN-STYLE-001
          when:
            source_role: [tool_output, memory_note]
            expected_interpretation: [data, analysis_target]
        - template_id: TMP-BENIGN-001
          when:
            source_role: [user]
            expected_interpretation: [instruction]
```

즉 대량 생성 모드에서는 `benign_template_id` 단일 값보다 `benign_template_pool`이 기본값이어야 한다.

## 26. 생성 알고리즘

### 26.1 pass 기반 생성

대량 생성 모드는 1회 전개가 아니라 `pass` 기반으로 돌린다.

권장 흐름:

1. family/template inventory 로드
2. family budget 계산
3. bundle 후보 생성
4. shard에 쓰기 전 local self-check
5. persistent dedup index 조회
6. 신규 후보만 shard에 append
7. build-equivalent preflight 수행
8. survivor/coverage deficit 계산
9. deficit가 남으면 다음 pass에서 refill

즉 “생성 -> 끝”이 아니라  
“생성 -> preflight -> 부족한 셀 refill”의 루프를 기본으로 둔다.

### 26.2 refill 우선순위

다음 우선순위를 권장한다.

1. coverage deficit가 있는 cell
2. survivor가 부족한 family
3. benign required contrast group이 부족한 family
4. KR/EN 비율이 무너진 family
5. 나머지 raw 확장

이 순서로 가야 20000 survivor에 가까워진다.

### 26.3 bundle pruning

대량 생성 모드는 bundle 후보를 전부 row로 펼치기 전에 아래 pruning을 먼저 해야 한다.

- template capability 밖 조합 제거
- family budget 초과 후보 제거
- 이미 index에 존재하는 bundle key 제거
- language ratio를 깨는 후보 제거
- benign pool 매칭 실패 후보 제거

즉 row 생성보다 candidate pruning이 앞에 와야 한다.

## 27. persistent dedup index

### 27.1 왜 필요한가

20000 survivor를 목표로 하면 실행마다 전체 후보를 다시 읽고 전체 dedup를 반복하는 것은 낭비가 크다.

따라서 generator 내부에 아래 수준의 경량 index를 둔다.

- exact payload hash index
- structural fingerprint index
- bundle key index
- contrast_group_id index

주의:

- build dedup를 대체하는 목적이 아니다.
- generator가 “명백히 살아남지 못할 후보”를 미리 거르는 목적이다.

### 27.2 index 저장 단위

권장 단위:

- key
- case_id
- shard_id
- family
- template_id
- created_at

이 정도면 재개와 회수 추적에 충분하다.

### 27.3 generator index와 build dedup의 관계

- generator index: 사전 차단용
- build dedup: 최종 판정용

둘의 기준이 어긋나면 안 되므로, generator index가 참조하는 envelope는 build dedup와 최대한 동일해야 한다.

최소 동기화 대상:

- exact payload hash 기준
- structural fingerprint 구성 필드
- mutation-sensitive dedup 계약
- contrast_group_id 포함 여부

## 28. coverage deficit-driven refill

### 28.1 기본 원칙

대량 생성 모드의 refill은 무작정 family 전체를 다시 늘리는 방식이 아니라, coverage 부족 셀을 직접 채우는 방식이어야 한다.

즉 preflight는 단순 fail/pass가 아니라 아래 정보를 generator에 되돌려줘야 한다.

- 어떤 profile에서
- 어떤 key cell이
- 몇 개 부족한지

### 28.2 refill 입력 형식

generator 내부 권장 deficit record:

```text
profile
+ key
+ required
+ observed
+ suggested families
```

예:

- `profile=release_default`
- `key=(ko, replay, indirect, replay_trajectory_injection)`
- `required=20`
- `observed=11`

이면 generator는 이 부족분을 가장 잘 메울 template/bundle 후보를 우선 생성한다.

### 28.3 refill 종료 조건

아래 중 하나에 도달하면 종료한다.

- `survivor_target` 달성
- 모든 coverage deficit 해소
- `max_passes` 도달
- pass당 신규 survivor 증가량이 임계치 이하

즉 장시간 무한 생성 루프를 피해야 한다.

## 29. CLI 설계

권장 명령:

```bash
pifuzz generate-cases \
  --templates catalogs/sample_templates.jsonl \
  --config configs/generator_bulk.yaml \
  --out catalogs/generated_cases.jsonl \
  --resume
```

- 1차 bulk 구현에서는 기존 CLI 호환을 우선한다.
- 따라서 bulk mode에서도 `--out`은 유지하고, 의미는 `output.export_jsonl` override로 둔다.
- bulk 내부 shard 저장 경로와 pass 운영은 config의 `output.out_dir`가 source of truth다.
- 즉 1차 구현에서 새 runtime override는 `--resume`까지만 우선 열고, `--out-dir`, `--export-jsonl`, `--max-passes`, `--target-survivors`, `--family` 같은 추가 override는 후속 단계에서 다시 판단한다.

후속 단계에서 검토할 수 있는 추가 옵션:

- `--export-jsonl`
- `--max-passes`
- `--target-survivors`
- `--family`

즉 대량 생성 모드는 `단발 실행`보다 `재개 가능한 배치 실행`에 맞춘 CLI가 필요하다.

## 30. 성공 기준

대량 생성 모드 성공 기준은 MVP보다 다르게 본다.

### 30.1 기능 기준

1. shard 단위 생성과 재개가 가능하다.
2. build-equivalent preflight 결과를 pass별로 기록한다.
3. persistent dedup index를 사용해 중복 생성을 줄인다.
4. family별 survivor, coverage deficit, benign linkage 현황을 요약할 수 있다.

### 30.2 규모 기준

1. `5000 raw / 2000 survivor`를 안정적으로 달성한다.
2. 이후 `15000 raw / 8000 survivor`를 재개 가능한 배치로 달성한다.
3. 최종적으로 `20000 survivor` 목표를 향해 `multi-pass refill`이 동작한다.

### 30.3 운영 기준

1. 중간 실패 후 `--resume`로 이어서 실행 가능하다.
2. shard 일부만 재생성해도 전체 manifest 정합성이 유지된다.
3. build export는 여전히 기존 `build`가 읽는 평평한 JSONL로 제공된다.

## 31. 구현 권장 순서

대량 생성 모드는 한 번에 다 붙이지 않는다.

1. `generator_MVP_설계.md`에 bulk mode 장 추가
2. `generator config`에 `mode`, `target_survivors`, `out_dir`, `shard_by` 추가
3. shard writer + manifest writer 추가
4. benign template pool 추가
5. persistent dedup index 추가
6. preflight summary를 family/cell 단위로 확장
7. deficit-driven refill pass 추가
8. `--resume` CLI 추가
9. `2000 survivor` 목표로 운영 검증
10. 이후 `20000 survivor` 목표로 budget 튜닝

즉 지금 당장 필요한 것은 “2만 건 최종 구현”이 아니라,  
나중에 2만 survivor까지 커져도 다시 뜯지 않도록 generator의 운영 단위를 `single file expansion`에서 `budgeted multi-pass sharded generation`으로 바꾸는 것이다.

## 32. 구현 계획 문서

대량 생성 모드의 실제 코드 작업은 별도 구현 계획 문서인 `generator_대량생성_구현_계획.md`를 기준으로 진행한다.
