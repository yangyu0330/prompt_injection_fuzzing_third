# Korean Axis Expansion Notes (Prompt Injection)

## Purpose
This note defines additional Korean-focused prompt injection axes to expand the current sample catalog.
PII-specific payload design is intentionally excluded in this phase.

## Priority Axes
### P0 (must-have)
- `jamo`
- `choseong`
- `kr_digits`
- `honorific_style`
- `code_switch`
- `document_context_laundering`
- `rag_chunk_boundary_split`
- `tool_output_poisoning`

### P1 (high-value)
- `spacing_particle_ending_variation`
- `hanja_romanization_mixed_script`
- `dialect_slang_neologism`
- `quoted_reply_footer_injection`
- `html_metadata_comment_injection`
- `table_csv_cell_injection`
- `memory_summary_poisoning`

### P2 (later)
- `ocr_noise_indirect`
- `approval_form_field_injection`
- `confirmation_bypass_framing`

## Collection Guidance
- Keep `Template -> Case -> Run` separation.
- Prefer slot-based payloads and placeholders over concrete unsafe strings.
- For Korean-focused axes, use `ko_only` cases where language-specific semantics are central.
- For comparison-sensitive axes, add KR/EN paired cases with invariant fields:
  - `user_goal`
  - `protected_asset`
  - `forbidden_action`
  - `tool_scope`
  - `entry_point`
  - `severity`

## Recommended Entry Point Mapping
- `document_context_laundering` -> `retrieved_document`, `email_body`, `quoted_reply`
- `rag_chunk_boundary_split` -> `retrieved_document`
- `tool_output_poisoning` -> `tool_output`, `memory_or_summary`
- `memory_summary_poisoning` -> `memory_or_summary`
- `approval_form_field_injection` -> `form_field`
- `html_metadata_comment_injection` -> `html_comment_or_metadata`

## Suggested Carriers
- `plain_chat`
- `markdown`
- `json`
- `table`
- `csv_like_table`
- `email_thread`
- `tool_result`
- `long_context_document`
- `ocr_text`
- `approval_form`

## Next Data Milestone
- For each P0 axis, add at least:
  - 1 template
  - 2+ cases
  - 1 L2/L3 executable path where applicable
- Add one benign sibling case per 3-4 new attack templates to keep over-blocking measurable.
