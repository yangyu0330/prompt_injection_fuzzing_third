from pi_fuzzer.prompt_guard_runtime import infer_detection


def test_infer_detection_uses_positive_label_hint() -> None:
    detected, label, score = infer_detection({"LABEL_0": 0.1, "LABEL_1": 0.9}, threshold=0.5)
    assert detected is True
    assert label == "LABEL_1"
    assert score == 0.9


def test_infer_detection_respects_negative_label_hint() -> None:
    detected, label, score = infer_detection({"safe": 0.95, "unsafe": 0.05}, threshold=0.2)
    assert detected is False
    assert label == "safe"
    assert score == 0.95


def test_infer_detection_falls_back_to_positive_candidates() -> None:
    detected, label, score = infer_detection(
        {
            "benign": 0.4,
            "prompt_injection": 0.7,
        },
        threshold=0.6,
    )
    assert detected is True
    assert label == "prompt_injection"
    assert score == 0.7
