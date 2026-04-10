# Generator 대량생성 구현 계획 (수정: 2026-04-10 16:35:13 KST)

## 상태

- 현재 코드 기준으로 1차 bulk mode는 이미 구현돼 있다.
- 구현 범위에는 `mode=bulk`, `--resume`, `output.out_dir`/`output.export_jsonl`, `manifest.json`, `summary.json`, `pass_reports/`, `indexes/`, `shards/`, adaptive seed-derivation planner, config probe pair planner, build-equivalent preflight, refill family 선택이 포함된다.
- 이 문서는 구현 순서 메모를 보존한 문서다. 현재 동작 계약은 코드와 운영 문서를 우선하고, 아래 본문은 왜 이런 구조로 구현했는지 추적하기 위한 참고 문맥으로 읽는 편이 맞다.
- 현재 `summary.json`과 pass report의 `family_shortfall`은 refill 힌트다. run status는 global `survivor_target`과 deficit 상태를 기준으로 계산되며, family shortfall이 남아 있어도 전체 status가 `success`일 수 있다.

## 1. 문서 목적

이 문서는 `generator_MVP_설계.md`에 정리된 `대량 생성 모드`를 실제 코드 작업으로 내리기 위한 구현 계획서다.

이 문서의 목표는 세 가지다.

1. 무엇을 먼저 만들고 무엇을 나중에 미룰지 범위를 고정한다.
2. 어떤 파일을 어떤 순서로 바꿀지 구현 단위를 고정한다.
3. 코드 작성 전에 완료 조건과 테스트 기준을 고정한다.

즉 이 문서는 방향 설명 문서가 아니라, `이 문서를 기준으로 바로 작업 계획을 세우고 코드에 들어갈 수 있는 문서`를 목표로 한다.

## 2. 구현 목표

### 2.1 최종 목표

- 장기 목표: `build 기준 survivor 20000`까지 확장 가능한 생성 구조 확보

### 2.2 이번 구현 목표

- 1차 구현 목표: `build 기준 survivor 2000`을 안정적으로 만들 수 있는 대량 생성 모드의 뼈대 구현
- 2차 구현 목표: 같은 구조를 유지한 채 `survivor 8000` 이상까지 올릴 수 있는 재개 가능 배치 구조 확보

중요:

- 이번 구현은 `20000 survivor 최종 완성`이 목표가 아니다.
- 이번 구현은 `20000 survivor까지 커져도 다시 뜯지 않아도 되는 구조`를 만드는 것이 목표다.

## 3. 이번 범위에서 반드시 지킬 결정

### 3.1 기존 MVP 모드는 유지한다

- 현재 `generate-cases`의 단일 파일 출력 경로는 유지한다.
- 대량 생성 모드는 `opt-in`이다.
- 즉 `mode=mvp`와 `mode=bulk`를 공존시킨다.

구체 계약:

- `mode=mvp`에서는 기존처럼 `--out`이 최종 JSONL 출력 경로다.
- `mode=bulk`에서도 `--out` 호환 옵션은 유지하되, 의미는 `output.export_jsonl` override로 둔다.
- bulk 내부 shard 저장 경로는 `output.out_dir`가 source of truth다.
- 즉 1차 구현에서는 `--out` 하나만으로 기존 CLI 호환성을 유지하고, 내부 운영 디렉터리 제어는 config가 담당한다.
- `--out` 같은 CLI override가 들어오면 resume 판단, manifest fingerprint, preflight 계약 검사는 원본 YAML이 아니라 override가 반영된 `effective config` 기준으로 수행한다.
- 1차 bulk 구현에서는 새 runtime override를 한꺼번에 열지 않는다. CLI override는 `--out`, `--resume`까지만 우선 고정하고, `--family`, `--target-survivors`, `--max-passes` 같은 추가 제어는 후속 단계에서 다시 판단한다.

### 3.2 최종 진실은 계속 build다

- 최종 split: build
- 최종 dedup: build
- 최종 coverage gate: build
- generator preflight는 build semantics를 미리 흉내내는 보조 수단일 뿐이다.

추가 계약:

- `preflight.build_config`는 최종 build에 실제로 쓸 config를 가리켜야 한다.
- 그 build config의 `case_sources`에는 effective `output.export_jsonl` 경로가 반드시 포함되어 있어야 한다.
- 이 조건이 깨지면 preflight와 최종 build가 서로 다른 입력 집합을 보게 되므로 bulk mode는 fail-fast 하는 편이 맞다.
- 다만 실제 bulk preflight 구현은 `export_jsonl`을 중복 로드하지 않도록 `case_sources`에서 해당 경로를 제외한 뒤, 현재 run의 committed generated rows를 정확히 한 번만 합쳐서 build-equivalent 평가를 수행해야 한다.

### 3.3 placeholder-only 원칙은 유지한다

- bulk mode에서도 자유 텍스트 생성은 하지 않는다.
- bulk mode는 여전히 metadata 조합기다.

### 3.4 build 입력은 계속 평평한 JSONL이다

- bulk 내부 운영은 shard로 간다.
- 하지만 build는 계속 `catalogs/generated_cases.jsonl` 같은 평평한 export 파일을 읽는다.
- 이 export 파일은 committed shard들을 기준으로 재구성하는 파생 산출물이다.
- resume 시 bulk mode는 `export_jsonl` 자체를 source of truth로 신뢰하지 않고, `manifest + committed shards + committed indexes`를 source of truth로 사용한다.

즉 내부 운영 구조와 외부 호환 인터페이스를 분리한다.

### 3.5 평가용 비교 규칙은 별도 문서로 분리한다

bulk 구현 계획 문서는 `대량 생성 모드를 어떤 순서로 구현할지`에 집중한다.

평가 관점의 비교 묶음 설계는 별도 문서인
`generator_평가비교묶음_설계.md`에서 다룬다.

이번 구현 계획에서 유지할 원칙은 아래와 같다.

- 생성 구조의 기본: 현재처럼 축 중심 조합과 bundle 중심 생성
- 평가용 비교 규칙: bulk 뼈대가 안정화된 뒤 별도 설계 문서를 기준으로 추가 검토

즉 이 문서는 구현 순서 문서이고, 평가 해석 규칙 문서는 따로 둔다.

## 4. 구현 산출물

이번 구현에서 새로 생기거나 바뀌는 산출물은 아래다.

| 구분 | 경로 | 역할 |
|---|---|---|
| 구현 | `src/pi_fuzzer/generator.py` | mode 분기와 공용 진입점 유지 |
| 구현 | `src/pi_fuzzer/generator_common.py` | MVP/bulk 공용 deterministic ID, linkage, self-check, preflight helper |
| 구현 | `src/pi_fuzzer/generator_bulk.py` | 대량 생성 모드 메인 로직 |
| 구현 | `src/pi_fuzzer/generator_bulk_index.py` | 대량 생성용 경량 색인 |
| 구현 | `src/pi_fuzzer/generator_bulk_report.py` | pass 요약, family 요약, deficit 요약 |
| 설정 | `configs/generator_bulk.yaml` | bulk mode 기본 설정 |
| 테스트 | `tests/test_generator_bulk.py` | bulk mode 전용 테스트 |
| 출력 | `catalogs/generated_bulk/` | shard, manifest, summary, index 저장 |
| export | `catalogs/generated_cases.jsonl` | build 입력용 합본 파일 |

주의:

- bulk 관련 구현을 전부 `generator.py` 한 파일에 누적하지 않는다.
- 기존 MVP와 bulk의 결합점을 최소화하기 위해 `generator.py`는 진입점 역할만 유지하는 편이 안전하다.
- 이미 `generator.py` 안에 들어 있는 deterministic ID, KR/EN linkage, benign linkage, build-equivalent preflight 같은 공용 primitive는 bulk 착수 전에 별도 공용 모듈로 추출하는 것을 기본 방침으로 둔다.
- split reassignment, coverage profile resolution, coverage gate, build-equivalent preflight helper는 `build.py`의 private underscore helper import에 기대지 않도록 공용 helper로 승격하는 편이 안전하다.

## 5. bulk mode의 최소 동작 정의

이번 구현에서 bulk mode는 아래 흐름이 돌아가면 된다.

1. template와 bulk config를 읽는다.
2. family budget을 계산한다.
3. row가 아니라 `bundle` 후보를 만든다.
4. bundle에서 attack/control/benign row를 컴파일한다.
5. local self-check를 수행한다.
6. shard에 저장한다.
7. committed shard를 기준으로 build export JSONL을 재구성한다.
8. build-equivalent preflight를 수행한다.
9. survivor 수와 coverage deficit를 요약한다.
10. 목표치가 모자라면 다음 pass로 refill한다.

이때 `--resume`이 켜져 있으면 기존 manifest와 index를 읽고 이어서 진행할 수 있어야 한다.

### 5.1 `--resume` 계약

`--resume`은 “같은 작업을 이어서 돌리는 경우”에만 허용한다.

- CLI 차원에서도 `--resume`은 `mode=bulk`에서만 유효하다.
- `mode=mvp`에서 `--resume`이 들어오면 조용히 무시하지 않고 fail-fast 한다.
- `--resume`이 없으면 같은 `out_dir`를 쓰더라도 새 run으로 시작하고, 기존 state를 암묵적으로 재사용하지 않는다.
- `--resume`이 없는데 `out_dir`에 기존 manifest/shard/index state가 남아 있으면 자동 덮어쓰기나 자동 정리를 하지 않고 fail-fast 하는 편이 안전하다.
- 즉 사용자는 새 `out_dir`를 주거나, 기존 state를 명시적으로 정리하거나, 정말 이어서 돌릴 의도일 때만 `--resume`을 사용해야 한다.

manifest에는 최소 아래 fingerprint가 남아 있어야 한다.

- effective generator config fingerprint
- build config fingerprint
- template source fingerprint
- curated case source fingerprint
- coverage matrix fingerprint
- seed
- 완료된 pass 목록
- shard 목록과 index 버전

원칙:

- 위 fingerprint가 모두 같을 때만 기존 shard/index를 재사용한다.
- 하나라도 달라지면 기존 index를 신뢰하지 않고 fail-fast 하거나 새 run으로 시작한다.
- 즉 `resume`은 편의 기능이지 stale index를 억지로 재사용하는 기능이 아니다.
- pass는 `tmp shard/tmp report`에 먼저 기록하고, atomic rename 후 index 갱신, export 재구성, preflight 완료까지 끝난 경우에만 `manifest.completed_passes`에 반영하는 편이 안전하다.
- resume 시 `tmp` 산출물은 재사용 대상이 아니며, committed shard와 index가 어긋나면 index를 shard 기준으로 재구성하거나 fail-fast 한다.

### 5.2 preflight deficit의 성격

preflight가 만드는 deficit은 전부 자동 refill 대상이 되는 것이 아니다.

- build coverage violation 원문은 그대로 보고한다.
- 그중 `bulk mode가 family/template 후보로 역추적 가능한 deficit`만 refill 입력으로 쓴다.
- 역추적이 불가능한 deficit은 `report-only deficit`으로 남기고 자동 refill 대상으로 쓰지 않는다.

## 6. bundle 기준 구현

### 6.1 왜 bundle이 먼저인가

bulk mode에서 핵심 단위는 row가 아니라 bundle이다.

이유:

- KR/EN pair를 함께 관리해야 한다.
- benign sibling을 contrast group 단위로 관리해야 한다.
- family budget도 실제로는 row보다 bundle 수로 잡는 편이 안정적이다.

### 6.2 이번 구현의 bundle key

1차 구현에서는 아래 축으로 bundle key를 만든다.

- `template_id`
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

원칙:

- `bundle_key`는 운영 키다.
- `semantic_equivalence_group`는 평가 키다.
- 둘은 같을 수도 있지만 개념적으로 분리한다.
- 현재 코드 기준 distinct scenario를 가르는 `policy_requested`, `delayed_injection_turn`은 planner가 bundle 내부 row 축으로 따로 관리하지 않는 한 `bundle_key`에도 포함하는 편이 안전하다.
- 즉 1차 구현의 `bundle_key`는 “대충 비슷한 것끼리 묶는 키”가 아니라, 현재 generator가 서로 다른 시나리오로 취급하는 축을 조용히 합치지 않는 수준까지는 닫혀 있어야 한다.

### 6.3 control row의 스키마 표현

문서 안에서 말하는 `attack/control/benign`은 3번째 top-level enum을 뜻하지 않는다.

- `attack_or_benign`은 계속 `attack | benign` 2값만 사용한다.
- 여기서 `control`은 독립 row type이 아니라 pair/contrast 안에서의 역할이다.
- 따라서 attack 계열 control row는 계속 `attack_or_benign=attack`으로 두고, `paired_case_role`로 역할을 구분한다.
- benign row만 `attack_or_benign=benign`으로 둔다.
- 1차 구현에서 `paired_case_role`의 canonical vocabulary는 최소 `attack`, `ko_variant`, `en_control`, `benign_control`로 고정하는 편이 안전하다.

즉 bulk mode는 새 enum을 추가하지 않고, 기존 `CaseRecord` 계약 안에서 control을 표현한다.

### 6.4 `semantic_equivalence_group` 규칙

bulk mode에서도 `semantic_equivalence_group`은 bundle key와 별도로 명시적으로 만든다.

최소 원칙:

- 같은 template에서 나왔더라도 `entry_point`, `source_role`, `expected_interpretation`이 다르면 기본적으로 다른 SEG로 본다.
- `carrier_context`, `tool_transition_type`, `replay_window`, `structured_payload_type`, `threshold_profile`, `normalization_variant`가 평가 의미를 바꾸면 SEG를 분리한다.
- 단순 운영상 bundle 분할이나 shard 분할 편의 때문에 SEG를 합치지 않는다.

이유:

- build split 배정과 split contamination 검사는 `semantic_equivalence_group`에 직접 걸린다.
- 따라서 SEG 규칙이 약하면 generated row 수는 늘어도 split 다양성과 coverage가 왜곡된다.

### 6.5 bundle과 평가 규칙은 분리한다

이번 구현에서 bundle은 아래 성격을 가진다.

- 현재 generator가 관리해야 하는 실제 생성 단위
- pair/linkage/coverage/dedup를 안정적으로 유지하기 위한 운영 단위

평가용 비교 규칙은 별도 문서에서 다루는 해석 단위다.

따라서 이번 bulk 구현에서는 아래 원칙만 유지한다.

- bundle: 지금 바로 구현
- 평가 규칙: bulk 안정화 이후 별도 문서 기준으로 추가 검토

즉 `운영 단위`와 `평가 단위`를 같은 것으로 두지 않는다.

## 7. bulk config 초안

권장 기본 구조는 아래다.

```yaml
generator:
  mode: bulk
  seed: 20260409
  mutation_recipe_path: catalogs/mutation_recipes.yaml
  raw_generated_target: 5000
  survivor_target: 2000
  max_passes: 4
  output:
    out_dir: catalogs/generated_bulk
    export_jsonl: catalogs/generated_cases.jsonl
    shard_by: family
    max_rows_per_shard: 1000
  preflight:
    enabled: true
    build_config: configs/build_generated_dev.yaml
    fail_on_survivor_shortfall: true
  dedup_index:
    enabled: true
    path: catalogs/generated_bulk/indexes
  contrast_policy:
    defaults:
      bilingual_pairing: true
      require_benign: false
    families:
      tool_agent_misuse:
        require_benign: true
        benign_template_pool:
          - template_id: TMP-KO-BENIGN-STYLE-001
            when:
              source_role: [tool_output, memory_note]
              expected_interpretation: [data, analysis_target]
  refill:
    enabled: true
    strategy: coverage_deficit_first
    driving_profiles: [release_default, p1_replay_tool_transition]
    min_new_survivors_per_pass: 100
  families:
    tool_agent_misuse:
      target_survivors: 700
      max_raw_rows: 1400
      max_bundles: 300
      priority: 100
      language_ratio:
        ko: 0.5
        en: 0.5
      benign_ratio_min: 0.2
```

이번 구현에서는 위 구조를 전부 한 번에 다 쓰지 않더라도, 필드 자리는 미리 열어두는 것이 좋다.

추가 메모:

- 위 예시의 `contrast_policy`는 3단계에서 실제로 사용할 최소 예시다.
- 1단계에서는 field 자리만 열어두고 `require_benign=false` 기본값으로 시작할 수 있지만, 3단계부터는 `require_benign=true` family에 대해 `benign_template_pool` 또는 그에 준하는 선택 규칙이 실제 config에 있어야 한다.

중요:

- `driving_profiles`는 build coverage profile 중 `자동 refill 입력으로 써도 되는 profile`만 가리킨다.
- refill-driving profile은 반드시 family/template 후보로 역추적 가능해야 한다.
- 권장 기본값은 `required_dims` 안에 `attack_family`를 포함하는 것이다.
- 현재 저장소의 `configs/build_generated_dev.yaml` 기준으로는 `release_default`, `p1_replay_tool_transition` 같은 profile이 기본 driving 후보에 가깝고, `p0_stage_role`은 추가 역추적 매핑 없이는 report-only로 두는 편이 안전하다.
- `attack_family`가 없는 profile을 driving profile로 쓰려면 bulk config에 `violation key -> suggested families/templates` 매핑을 따로 둬야 한다.
- 역추적 불가능한 profile은 preflight 보고용으로만 쓰고 refill 입력으로는 쓰지 않는다.
- `preflight.build_config`가 가리키는 build config에는 `output.export_jsonl`이 `case_sources`에 포함되어 있어야 한다.
- bulk mode는 시작 시 이 계약을 검사하고, 어긋나면 preflight를 계속 진행하지 않고 바로 실패시키는 편이 안전하다.
- family target과 shortfall 집계는 generated row 기준으로 계산하고, curated row는 coverage 충족에는 기여하더라도 family budget 달성치에는 포함하지 않는다고 미리 못 박는 편이 안전하다.

family budget 필드 의미:

- `target_survivors`: 해당 family가 현재 run에서 생성한 row들 중 최종 build semantics를 지난 뒤 확보하고 싶은 누적 survivor 목표다. pass별 quota가 아니라 run 전체의 soft target이다.
- `max_raw_rows`: 해당 family에 속한 bundle들이 export JSONL에 추가할 수 있는 누적 raw row hard cap이다. pass를 넘어 합산한다.
- `max_bundles`: 해당 family planner가 run 전체에서 생성할 수 있는 누적 bundle hard cap이다.
- `priority`: 여러 family가 동시에 deficit을 가질 때 refill 우선순위를 정하는 정렬 키다. 높은 값 우선으로 두는 편이 단순하다.
- `language_ratio`: 해당 family의 attack 계열 row 분배 목표다. 1차 planner는 emitted row 기준으로 맞추고, refill 보정은 preflight survivor 기준의 부족분을 사용한다고 분리해 두는 편이 안전하다.
- `benign_ratio_min`: 해당 family bundle에서 파생된 전체 emitted row 기준 최소 benign 비율이다. bundle 수 기준이 아니라 row 수 기준으로 해석한다고 못 박아 두는 편이 맞다.
- generated row가 curated row 또는 기존 generated row에 밀려 dedup drop 된 경우는 family report에서 `generated drop`으로 분리해 기록하는 편이 안전하다.
- 즉 family budget은 planner 입력은 bundle 중심이지만, 일부 비율 필드와 survivor/shortfall 집계는 compile 이후 row 기준 또는 preflight survivor 기준으로 해석한다고 문서에서 분리해 두는 것이 좋다.

## 8. 출력 구조

### 8.1 내부 출력

```text
catalogs/generated_bulk/
  manifest.json
  summary.json
  pass_reports/
    pass-0001.json
    pass-0002.json
  shards/
    family=tool_agent_misuse/part-0001.jsonl
    family=replay_trajectory_injection/part-0001.jsonl
  indexes/
    bundle_index.jsonl
    exact_hash_index.jsonl
    structural_fingerprint_index.jsonl
```

`manifest.json` 최소 포함 항목:

- generator/build/template/case/coverage 관련 fingerprint
- seed
- 완료된 pass 목록
- shard 목록
- index schema/version
- resume 가능 여부 판단에 필요한 상태 값
- `tmp` 산출물을 제외한 committed shard 목록
- `output.export_jsonl`이 shard 파생 산출물이라는 사실을 복원할 수 있는 상태 값

`summary.json` 최소 포함 항목:

- 최종 survivor 수
- driving deficit 수
- report-only deficit 수
- 종료 사유
- 최종 상태값

권장 상태값:

- `success`
- `success_with_report_only_deficits`
- `success_with_survivor_shortfall`
- `failed_survivor_shortfall`
- `failed_config_mismatch`

추가 계약:

- `success*` 상태는 exit code 0으로, `failed_*` 상태는 non-zero exit으로 매핑하는 편이 안전하다.
- 실패 종료여도 `manifest.json`, `summary.json`, 마지막 committed `pass_report`는 남겨서 `--resume`과 운영 디버깅에 사용할 수 있어야 한다.

### 8.2 외부 출력

- `catalogs/generated_cases.jsonl`

이 파일은 bulk 내부 shard를 합쳐 만든 build용 export다.

원칙:

- `export_jsonl`은 committed shard들에서 매번 재구성 가능한 파생 산출물이다.
- resume는 `export_jsonl` 자체를 신뢰하지 않고, 필요 시 shard 기준으로 export를 다시 만든다.

## 9. 단계별 구현 계획

## 9.0 선행 작업: 공용 primitive 분리

목표:

- 기존 `generator.py` 안의 MVP/bulk 공용 primitive를 별도 모듈로 추출한다.
- 이후 bulk mode와 MVP mode가 동일한 deterministic ID, linkage, self-check, preflight 계약을 재사용하게 만든다.
- build-equivalent preflight를 위해 필요한 split/coverage/dedup helper도 공용 경로로 옮겨 `build.py` private helper 의존을 줄인다.

변경 파일:

- `src/pi_fuzzer/generator.py`
- `src/pi_fuzzer/generator_common.py`
- `tests/test_generator.py`

완료 조건:

- `generator.py`는 진입점과 mode 분기 중심으로 가벼워진다.
- 공용 deterministic ID / SEG / linkage / preflight helper가 분리된다.
- MVP 기존 테스트가 그대로 통과한다.
- `generator_common.py`는 bulk가 build private underscore helper를 직접 import하지 않아도 되도록 공용 helper를 제공한다.

테스트:

- `mode=mvp` 회귀 테스트
- 공용 helper 재사용 테스트

## 9.1 1단계: bulk mode 진입점과 출력 디렉터리

목표:

- `generate-cases`가 `mode=bulk`를 읽고 bulk 전용 루틴으로 분기한다.
- `out_dir`, `export_jsonl`을 사용하는 기본 출력 구조를 만든다.
- 기존 `--out` CLI 계약을 bulk mode에서도 깨지 않게 정리한다.

변경 파일:

- `src/pi_fuzzer/generator.py`
- `src/pi_fuzzer/generator_common.py`
- `src/pi_fuzzer/generator_bulk.py`
- `configs/generator_bulk.yaml`

완료 조건:

- bulk mode 실행 시 출력 디렉터리와 manifest 기본 파일이 생성된다.
- 기존 MVP mode는 그대로 동작한다.
- `mode=bulk`에서 `--out`은 `export_jsonl` override로 동작한다.
- `output.out_dir`는 config 기준으로 결정된다.

테스트:

- `mode=mvp` 회귀 테스트
- `mode=bulk` 기본 디렉터리 생성 테스트
- `mode=bulk`에서 `--out` override 테스트

## 9.2 2단계: bundle planner와 shard writer

목표:

- row 단위가 아니라 bundle 단위로 후보를 만든다.
- family별 shard에 row를 쓴다.
- export JSONL을 생성한다.

변경 파일:

- `src/pi_fuzzer/generator_bulk.py`
- `tests/test_generator_bulk.py`

완료 조건:

- shard에 row가 분산 저장된다.
- export JSONL은 build가 읽을 수 있는 완성 `CaseRecord` JSONL이다.
- 같은 입력이면 같은 shard 배치와 같은 case_id를 유지한다.
- 같은 입력이면 같은 `semantic_equivalence_group` 배치도 유지한다.
- bundle key와 SEG가 분리되어도 split contamination을 일으키지 않는다.

테스트:

- deterministic shard layout 테스트
- export JSONL 파싱 테스트
- deterministic SEG 생성 테스트
- split contamination self-check 테스트

## 9.3 3단계: benign template pool과 contrast bundle

목표:

- 단일 benign template이 아니라 조건부 benign pool을 지원한다.
- bundle 단위에서 attack/control/benign linkage를 일관되게 만든다.

변경 파일:

- `src/pi_fuzzer/generator_bulk.py`
- `configs/generator_bulk.yaml`
- `tests/test_generator_bulk.py`

완료 조건:

- source_role / expected_interpretation 조건에 맞는 benign template가 선택된다.
- `benign_sibling_id`, `contrast_group_id`, `paired_case_role`가 bundle 단위로 일관된다.
- attack 계열 control row는 새 enum 없이 기존 `attack_or_benign=attack` + `paired_case_role` 계약으로 표현된다.
- `require_benign=true`인 contrast group은 attack row들과 동일한 `contrast_group_id`를 공유하는 benign row를 정확히 1개 가진다.

테스트:

- benign pool 조건 매칭 테스트
- contrast group별 linkage 테스트
- control row 스키마 표현 테스트

## 9.4 4단계: preflight 요약과 family별 부족분 계산

목표:

- 단순 pass/fail이 아니라 family별 survivor 수와 부족한 coverage cell을 요약한다.
- bulk mode가 다음 pass에서 무엇을 더 만들어야 하는지 계산할 수 있게 한다.
- deficit을 `refill-driving`과 `report-only`로 구분한다.

변경 파일:

- `src/pi_fuzzer/generator_common.py`
- `src/pi_fuzzer/generator_bulk_report.py`
- `tests/test_generator_bulk.py`

완료 조건:

- preflight 요약에 최소 아래가 포함된다.
  - 총 input row 수
  - 총 survivor 수
  - family별 input/survivor/drop 수
  - coverage deficit 목록
- coverage deficit마다 `driving 가능 여부`가 명시된다.
- driving deficit은 어떤 family/template 후보로 연결되는지 계산 가능해야 한다.
- `preflight.build_config`와 `output.export_jsonl`의 계약 불일치가 검출된다.
- preflight는 `export_jsonl`을 중복 로드하지 않고 committed generated rows를 정확히 한 번만 평가한다.
- family별 survivor/drop 집계는 generated rows 기준 집계와 combined build scope 집계를 혼동하지 않도록 분리된다.

테스트:

- preflight report 구조 테스트
- family별 survivor 집계 테스트
- driving/report-only deficit 분리 테스트
- build config에 export path 누락 시 fail-fast 테스트

## 9.5 5단계: persistent dedup index와 resume

목표:

- 이미 생성된 bundle과 명백한 중복 row를 재생성하지 않도록 색인을 둔다.
- 실행 중단 후 `--resume`으로 이어서 돌릴 수 있게 한다.

변경 파일:

- `src/pi_fuzzer/generator_bulk_index.py`
- `src/pi_fuzzer/generator_bulk.py`
- `src/pi_fuzzer/cli.py`
- `tests/test_generator_bulk.py`

완료 조건:

- `--resume` 시 기존 manifest와 index를 읽는다.
- 이미 기록된 bundle은 건너뛴다.
- 이미 기록된 exact hash / structural fingerprint는 사전 차단한다.
- manifest fingerprint가 현재 입력과 다르면 stale resume을 거부한다.
- `mode=mvp`에서 `--resume`이 들어오면 fail-fast 한다.
- generator dedup index의 exact hash / structural fingerprint는 build dedup와 같은 함수를 재사용한다.
- pass commit은 tmp write -> atomic rename -> index update -> export 재구성 순서로 수행한다.
- committed shard와 index 불일치가 발견되면 index를 shard 기준으로 재구성하거나 resume을 거부한다.

테스트:

- resume 후 중복 생성 방지 테스트
- index 재사용 테스트
- fingerprint mismatch 시 resume 거부 테스트
- `mode=mvp` + `--resume` 거부 테스트
- build dedup fingerprint parity 테스트
- tmp shard crash recovery 테스트

## 9.6 6단계: deficit-driven refill

목표:

- preflight 결과를 바탕으로 부족한 family와 부족한 coverage cell을 우선 채운다.
- pass 기반 루프가 실제로 목표 survivor 수를 향해 수렴하도록 만든다.
- 단, 역추적 불가능한 deficit은 자동 refill하지 않고 report-only로 남긴다.

변경 파일:

- `src/pi_fuzzer/generator_bulk.py`
- `src/pi_fuzzer/generator_bulk_report.py`
- `tests/test_generator_bulk.py`

완료 조건:

- 최소 2회 pass가 가능하다.
- 1차 pass 대비 2차 pass에서 부족한 family/cell이 실제로 줄어든다.
- `max_passes`, `min_new_survivors_per_pass` 종료 조건이 동작한다.
- `driving_profiles`에 포함된 deficit만 refill 입력으로 소비된다.
- 남은 deficit이 전부 report-only이면 refill 루프를 종료한다.
- 이때 survivor 부족이 남아 있고 `fail_on_survivor_shortfall=true`면 산출물을 남긴 뒤 non-zero 종료로 처리한다.
- survivor 부족이 남아 있지만 `fail_on_survivor_shortfall=false`면 zero exit으로 종료하고 상태값은 `success_with_survivor_shortfall`로 둔다.
- survivor 부족이 없고 report-only deficit만 남으면 `success_with_report_only_deficits`로 종료한다.
- survivor 부족과 report-only deficit이 동시에 남아도 상태 우선순위는 shortfall 쪽이 더 크므로 `success_with_survivor_shortfall` 또는 `failed_survivor_shortfall`로 기록하는 편이 단순하다.
- 종료 전에는 항상 `summary.json`과 `manifest.json`을 flush한 뒤 exit code를 결정한다.

테스트:

- refill 우선순위 테스트
- pass 종료 조건 테스트
- non-invertible deficit report-only 처리 테스트
- report-only deficit만 남았을 때 종료 상태 테스트
- `fail_on_survivor_shortfall=false`일 때 shortfall 허용 종료 상태 테스트

## 10. 바로 구현하지 않을 것

이번 구현에서는 아래를 넣지 않는다.

- 데이터베이스 저장소
- 분산 처리
- 여러 프로세스 병렬 샤드 생성
- 자유 텍스트 생성
- `release + hybrid` 최적화 전용 고급 탐색
- 평가용 비교 묶음의 generator 내장

이 항목들은 bulk mode가 `2000 survivor`를 안정화한 뒤에 판단한다.

## 11. 테스트 전략

이번 bulk mode는 기존 generator보다 테스트 비중이 더 높아야 한다.

필수 테스트 묶음:

1. bulk mode 진입과 기본 출력 구조
2. shard writer와 export JSONL
3. bundle deterministic 생성
4. deterministic SEG 생성과 split contamination 방지
5. benign pool 선택
6. contrast linkage 정합성
7. bulk CLI `--out` 호환 유지
8. preflight family 요약
9. build config/export path 계약 검증
10. dedup index 재사용
11. resume
12. stale resume 거부
13. refill 루프
14. report-only deficit 분리
15. report-only deficit 종료 상태
16. `fail_on_survivor_shortfall=false` 종료 상태
17. `mode=bulk` 전용 `--resume` 계약
18. 기존 MVP mode 회귀
19. 평가 규칙은 별도 문서에서 다루고, bulk 구현 테스트와 분리
20. preflight의 export 중복 집계 방지
21. shard 기준 export 재구성
22. stale export 무시
23. build dedup fingerprint parity
24. tmp 파일 crash recovery
25. 실패 종료 시 summary/manifest flush
26. `--out` override가 effective config fingerprint에 반영되는지 검증

원칙:

- bulk mode 기능은 가능하면 작은 fixture로 검증한다.
- 실제 대량 데이터 테스트는 단위 테스트가 아니라 수동 검증 스크립트 수준으로 분리한다.

## 12. 완료 정의

이번 구현은 아래를 만족하면 1차 완료로 본다.

1. `mode=bulk`가 실제로 동작한다.
2. shard와 export JSONL이 함께 생성된다.
3. build-equivalent preflight 요약이 남는다.
4. `--resume`이 동작한다.
5. family별 survivor 부족분을 보고 다음 pass를 돌릴 수 있다.
6. `survivor 2000`을 목표로 하는 설정 파일을 넣고 구조적으로 확장 가능한 상태가 된다.
7. 후속 평가 규칙을 얹을 수 있는 구조가 확보된다.
8. stale manifest/index를 재사용하지 않는 resume 안전장치가 있다.
9. `mode=mvp`와 `mode=bulk`의 CLI 계약이 `--out`, `--resume` 기준으로 충돌하지 않는다.
10. `export_jsonl`이 shard 파생 산출물이라는 계약과 preflight 중복 집계 방지 규칙이 지켜진다.
11. 실패 종료 시에도 `summary.json`/`manifest.json`이 남아 재개와 디버깅이 가능하다.

## 13. 코드 착수 순서

실제 코드는 아래 순서로 들어가는 것이 가장 안전하다.

1. `generator.py` 안의 공용 primitive를 `generator_common.py`로 분리
2. `configs/generator_bulk.yaml` 추가
3. `generator.py`에 mode 분기 추가
4. `generator_bulk.py`에 shard writer + export writer 추가
5. bundle planner + deterministic SEG 추가
6. benign pool 추가
7. preflight report 확장
8. dedup index + resume 추가
9. refill pass 추가
10. `tests/test_generator_bulk.py` 보강
11. 이후 필요 시 별도 평가 규칙 추가

즉 첫 bulk 기능 코드는 `refill`이 아니라 `공용 primitive 분리 + mode 분기 + shard/export 구조`부터 시작하는 것이 맞다.

## 14. 한 줄 요약

이 구현 계획의 핵심은 대량 생성 모드를 “한 번에 많이 만드는 기능”이 아니라,  
`묶음 단위 생성 + shard 저장 + build 기준 사전점검 + 부족분 재보충`을 반복하는 배치 생성 구조로 먼저 구현하고,  
평가용 비교 규칙은 그 위에 후속 단계로 얹는 것이다.
