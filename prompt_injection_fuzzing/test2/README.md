# Test2: Prompt Injection Fuzzer 명세 + 샘플 패키지

## 1. 문서 목적

`test2`는 프롬프트 인젝션 퍼저를 실제 구현으로 넘기기 직전 단계의 명세 고정 패키지다. 이 단계의 목표는 코드를 많이 작성하는 것이 아니라, 이후 `test3`에서 데이터 수집과 정규화, 렌더링, 러너 구현을 할 때 해석 차이가 생기지 않도록 입출력 계약과 샘플 형식을 먼저 고정하는 데 있다.

이 패키지는 아래 두 문서의 설계를 구현 가능한 산출물로 압축한다.

- 루트 설계 문서 `prompt_injection_fuzzer_design_plan_ko_en.md`
- 루트 계획 문서 `PLAN.md`

중요한 전제는 다음과 같다.

- `test2`에서는 외부 데이터셋을 실제로 다운로드하거나 병합하지 않는다.
- `test2`에서는 스키마, 샘플, 소스 매핑 규칙, 러너 계약만 정의한다.
- `test2`의 샘플은 모두 synthetic 안전 데이터를 사용한다.
- 실제 PII, 실제 비밀값, 실제 계정 정보는 포함하지 않는다.

## 2. 이 패키지에 포함된 것

`test2`는 아래 4개 묶음으로 구성된다.

- `spec`: canonical case, rendered case, judge event, run result, layer export의 JSON Schema
- `samples`: EN-KO paired, KO-native, hard negative를 포함한 예시 JSONL/JSON
- `mapping`: 외부 데이터셋별 역할, 허용 split, 금지 split, 라이선스 처리 규칙
- `runner_contract`: Layer 1~4 러너가 지켜야 하는 입력/출력 계약과 집계 키

즉, `test2`는 “프롬프트 인젝션 퍼저를 어떤 파일 구조와 어떤 타입으로 구현할 것인가”를 고정하는 패키지다.

## 3. 디렉터리 구조

```text
test2/
  README.md
  runner_contract.md
  prompt_injection_fuzzer_design_plan_ko_en.md
  spec/
    canonical_case.schema.json
    rendered_case.schema.json
    judge_event.schema.json
    run_result.schema.json
    layer_exports.schema.json
  samples/
    canonical_cases.sample.jsonl
    rendered_cases.sample.jsonl
    judge_events.sample.jsonl
    run_results.sample.jsonl
    layer_exports.sample.json
  mapping/
    source_mapping.yaml
    split_policy.yaml
  scripts/
    validate_test2.py
```

각 경로의 역할은 아래와 같다.

- `README.md`: 패키지 목적, 구현 순서, 검증 방법 안내
- `runner_contract.md`: 레이어별 실행 입력/출력 계약 문서
- `prompt_injection_fuzzer_design_plan_ko_en.md`: 설계 근거와 구조적 의사결정 문서
- `spec/`: 후속 코드가 반드시 따라야 하는 타입 정의
- `samples/`: 스키마 검증과 러너 초기 개발에 쓰는 샘플 데이터
- `mapping/`: 외부 데이터셋을 실제 수집할 때 따라야 하는 정책 문서
- `scripts/validate_test2.py`: 스키마와 샘플, split hygiene를 검증하는 스크립트

## 4. 고정된 구현 순서

이 패키지는 구현 순서를 아래 6단계로 고정한다.

1. `normalize`
2. `render`
3. `export`
4. `run`
5. `judge`
6. `report`

각 단계의 의미는 다음과 같다.

### 4.1 `normalize`

외부 데이터셋이나 내부 자가 작성 seed를 공통 IR 형태의 canonical case로 변환한다. 이 단계에서 언어, 공격면, 캐리어, 목표, split, hard negative 여부를 표준 필드로 정리한다.

### 4.2 `render`

canonical case를 실제 실행 가능한 입력으로 펼친다. 여기서 `rendered_system`, `rendered_user`, `rendered_context`, `mutation_names`, `judge_spec`가 결정된다.

### 4.3 `export`

rendered case를 Layer별 실행 파일 형식으로 내보낸다. 예를 들어 L1 입력 차단용 세트, L4 RAG 문서 세트, hard negative eval 세트를 분리해 생성한다.

### 4.4 `run`

각 Layer 러너가 export 파일을 읽어 detector, gateway, LLM, RAG 환경에서 실제 실행한다. 이 단계의 산출물은 `run_result`다.

### 4.5 `judge`

실행 결과를 `judge_event` 기준으로 판정한다. detector가 막았는지, 놓쳤는지, LLM이 지시를 따랐는지, canary나 synthetic secret이 노출됐는지를 기록한다.

### 4.6 `report`

집계 키 기준으로 레포트를 생성한다. 기존 PII 프레임워크의 `by_level`, `by_mutation`, `by_type`, `by_tier`, `by_lang`는 유지하고, prompt injection 전용 키를 추가한다.

## 5. 핵심 설계 원칙

### 5.1 단일 payload 파일 공유를 폐기한다

더 이상 하나의 거대한 payload 파일을 팀 공통 자산으로 두지 않는다. 대신 하나의 canonical corpus를 기준으로 각 Layer export를 생성한다. 즉, 공유 단위는 “문장 모음”이 아니라 “정규화된 seed와 export 규칙”이다.

### 5.2 PII 중심 정의를 쓰지 않는다

이 퍼저의 목표는 실제 개인정보 탐지가 아니라 prompt injection 탐지/차단과 그 실패 양상을 측정하는 것이다. 따라서 출력 신호도 실제 PII가 아니라 `canary`, `prompt leak marker`, `synthetic secret`, `synthetic tool/action`으로 제한한다.

### 5.3 한국어는 별도 축으로 본다

한국어는 영어 seed 번역만으로 품질이 나오지 않는다. `EN-KO paired`와 `KO-native`를 분리하고, KO-native에는 자모분리, 초성, 한글숫자, 띄어쓰기 붕괴, 조사 변형, 코드스위칭, zero-width/fullwidth 같은 변이를 필수로 넣는다.

### 5.4 hard negative를 평가 본체에 포함한다

좋은 프롬프트 인젝션 퍼저는 공격만 많이 모은 코퍼스가 아니다. 정상 문서, 보안 교육 문서, README, 설치 가이드, 안전하지만 명령형 문장 같은 hard negative가 충분히 있어야 false positive를 측정할 수 있다.

### 5.5 Layer 4에는 악성 retrieved content가 반드시 있어야 한다

RAG나 repo 기반 간접 인젝션은 정상 문서만 넣어서는 측정이 안 된다. 이메일 회신 체인, footer, hidden instruction, CI config, README 지시문, chunk split payload가 실제로 들어간 문서 세트가 있어야 한다.

## 6. 검증 방법

아래 명령으로 `test2` 패키지를 검증한다.

```bash
python test2/scripts/validate_test2.py
```

이 스크립트는 아래 항목을 검사한다.

- 모든 샘플 파일이 각 JSON Schema를 통과하는지
- 필수 필드 누락, 타입 오류, enum 외 값이 없는지
- 동일 `family_id`가 여러 split에 중복되지 않는지
- EN-KO pair가 동일 `family_id`와 동일 split을 공유하는지
- KO-native 샘플이 EN-KO pair와 분리 태깅돼 있는지
- canonical sample에서 hard negative 비율이 최소 20%인지
- Layer export에 direct, indirect, email, repo, multi-turn, tool-redirection, hard-negative가 모두 포함되는지
- 결과 계약에 필요한 report key가 모두 선언돼 있는지

## 7. 안전 정책

이 패키지는 synthetic 목표만 허용한다.

- `canary`
- `synthetic secret`
- `synthetic tool/action`

금지 대상은 아래와 같다.

- 실제 주민등록번호, 여권번호, 계좌번호
- 실제 API 키, 실제 비밀번호, 실제 토큰
- 실제 사내 시스템 호출 정보
- 실제 외부 서비스 계정 또는 전송 대상

## 8. 다음 단계에서 해야 할 일

`test2` 다음 단계인 `test3`에서는 아래를 수행하면 된다.

1. `mapping/` 정책에 따라 외부 데이터셋을 수집한다.
2. 각 소스를 canonical schema로 정규화한다.
3. EN-KO paired와 KO-native를 별도 경로로 렌더링한다.
4. Layer별 export 파일을 생성한다.
5. 러너를 구현해 `run_result`와 `pi_stats`를 출력한다.

즉, `test2`는 구현을 멈추는 단계가 아니라 구현 기준을 얼리는 단계다.
