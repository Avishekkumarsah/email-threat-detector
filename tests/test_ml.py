from backend.app.ml.inference import analyze_content, get_model_status


def test_ml_inference_phishing():
    status = get_model_status()
    assert status["status"] == "loaded"

    result = analyze_content(
        "Urgent: Your account has been suspended",
        "Please click here to verify your account immediately or your access will be permanently terminated.",
    )
    assert result["phishing_probability"] > 40
    assert result["classification"] in ["Suspicious", "Likely Phishing"]
    assert len(result["keyword_flags"]) > 0


def test_ml_inference_legitimate():
    result = analyze_content(
        "Weekly Project Meeting Notes",
        "Hi team, attached are the discussion points from yesterday's meeting. Thanks for your contributions.",
    )
    assert result["phishing_probability"] < 50
    assert result["classification"] in ["Likely Legitimate", "Suspicious"]
