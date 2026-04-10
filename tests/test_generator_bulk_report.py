from pi_fuzzer.generator_bulk_report import classify_deficits


def test_classify_deficits_marks_new_driving_profiles_when_family_is_invertible() -> None:
    violations = [
        {
            "profile": "bulk_full_family_set",
            "kind": "required_value",
            "key": ["attack_family", "adaptive_fuzzing"],
            "dims": ["attack_family"],
            "count": 0,
            "required": 1,
        },
        {
            "profile": "repo_surface_axes",
            "kind": "required_combination",
            "key": [
                "attack_family=repo_coding_agent_injection",
                "entry_point=file_text",
                "carrier_context=repo_file",
            ],
            "dims": ["attack_family", "entry_point", "carrier_context"],
            "count": 0,
            "required": 1,
        },
        {
            "profile": "config_probe_axes",
            "kind": "required_value",
            "key": ["attack_family", "config_sensitivity_probe"],
            "dims": ["attack_family"],
            "count": 0,
            "required": 1,
        },
    ]

    driving, report_only = classify_deficits(
        violations,
        driving_profiles={"bulk_full_family_set", "repo_surface_axes", "config_probe_axes"},
        family_hints={},
    )

    assert len(driving) == 3
    assert report_only == []

    suggested = {item["profile"]: item["suggested_families"] for item in driving}
    assert suggested["bulk_full_family_set"] == ["adaptive_fuzzing"]
    assert suggested["repo_surface_axes"] == ["repo_coding_agent_injection"]
    assert suggested["config_probe_axes"] == ["config_sensitivity_probe"]


def test_classify_deficits_keeps_non_invertible_as_report_only() -> None:
    violations = [
        {
            "profile": "config_probe_axes",
            "kind": "required_value",
            "key": ["threshold_profile", "strict"],
            "dims": ["threshold_profile"],
            "count": 0,
            "required": 1,
        }
    ]

    driving, report_only = classify_deficits(
        violations,
        driving_profiles={"config_probe_axes"},
        family_hints={},
    )

    assert driving == []
    assert len(report_only) == 1
