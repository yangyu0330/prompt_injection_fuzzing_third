from __future__ import annotations

import pytest

from pi_fuzzer.engine import load_target_config


def test_load_target_config_rejects_unknown_response_adapter(tmp_path) -> None:
    cfg_path = tmp_path / "target.yaml"
    cfg_path.write_text(
        "\n".join(
            [
                "target_id: test-target",
                "mode: text_only",
                "transport: http",
                "url: http://localhost:9999/evaluate",
                "response_field_map:",
                "  detected: result.detected",
                "response_adapter: does_not_exist",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsupported response_adapter"):
        load_target_config(cfg_path)
