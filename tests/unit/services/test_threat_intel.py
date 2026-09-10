from __future__ import annotations

from threat_hunting.services.threat_intel import compare_advisory_iocs, extract_advisory_iocs, query_ioc_context


def test_filename_match_does_not_make_a_different_hash_match() -> None:
    advisory = query_ioc_context("a" * 64 + " file:name = 'tool.exe'")

    assert compare_advisory_iocs({"file_name": "tool.exe", "file_hash": "b" * 64}, advisory) == {
        "hash_literals": [{"observed_value": "b" * 64, "matches_extracted_advisory_hash": False}],
        "matched_file_name_literals": ["tool.exe"],
        "matched_domain_literals": [],
    }


def test_hash_comparisons_use_full_values_and_preserve_conflicting_projected_and_raw_values() -> None:
    import json

    advisory = query_ioc_context("a" * 64 + " " + "c" * 40 + " " + "d" * 32)
    result = {
        "file_hash": ["a" * 64, "a" * 64, "C" * 40, "d" * 32],
        "_raw": json.dumps({"file_hash": "b" * 64}),
        "command_line": "--hash=" + "a" * 64,
    }
    comparisons = compare_advisory_iocs(result, advisory)

    assert comparisons["hash_literals"] == [
        {"observed_value": value, "matches_extracted_advisory_hash": match}
        for value, match in [("a" * 64, True), ("C" * 40, True), ("d" * 32, True), ("b" * 64, False)]
    ]
    assert result["file_hash"] == ["a" * 64, "a" * 64, "C" * 40, "d" * 32]


def test_missing_hash_and_substrings_are_not_negative_hash_comparisons() -> None:
    advisory = query_ioc_context("a" * 64 + " file:name = 'tool.exe' domain-name:value = 'example.test'")
    result = {
        "file_name": "tool.exe",
        "path": "/tmp/tool.exe",
        "command_line": "tool.exe --hash=" + "a" * 64,
        "dns": ["example.test", "sub.example.test"],
    }

    assert compare_advisory_iocs(result, advisory) == {
        "hash_literals": [],
        "matched_file_name_literals": ["tool.exe"],
        "matched_domain_literals": ["example.test"],
    }
    assert compare_advisory_iocs({"path": "/tmp/tool.exe", "file_name": "TOOL.EXE"}, advisory)["matched_file_name_literals"] == []


def test_empty_advisory_does_not_imply_a_missing_observed_hash() -> None:
    comparison = compare_advisory_iocs({"file_hash": "b" * 64}, query_ioc_context(""))

    assert comparison["hash_literals"] == [{"observed_value": "b" * 64, "matches_extracted_advisory_hash": False}]


def test_extract_advisory_iocs_reads_only_stix_indicator_patterns() -> None:
    iocs = extract_advisory_iocs("""{
      "objects": [
        {"type": "indicator", "pattern": "[file:hashes.'SHA-256' = '7dea671be77a2ca5772b86cf8831b02bff0567bce6a3ae023825aa40354f8aca' AND file:name = 'HRsword.exe']"},
        {"type": "note", "content": "file:hashes.'SHA-256' = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'"}
      ]
    }""")

    assert iocs["sha256"] == ["7DEA671BE77A2CA5772B86CF8831B02BFF0567BCE6A3AE023825AA40354F8ACA"]
    assert iocs["file_names"] == ["HRsword.exe"]
    assert iocs["domains"] == []


def test_query_context_preserves_hash_values_without_source_enum_assumptions() -> None:
    values = ["a" * 64, "b" * 40, "c" * 32]
    text = " ".join([*values, values[0], "file:name = 'tool.exe'", "domain-name:value = 'example.test'"])
    context = query_ioc_context(text)
    assert context == {"file_hashes": [value.upper() for value in values], "file_names": ["tool.exe"], "domains": ["example.test"]}
    assert extract_advisory_iocs(text)["sha256"] == [values[0].upper()]
def test_advisory_identity_is_bound_to_the_hunt_and_exact_input_content():
    from threat_hunting.services.threat_intel import intelligence_sources

    first = intelligence_sources("hunt-one", "advisory")
    assert first == intelligence_sources("hunt-one", "advisory")
    assert first[0]["source_id"] != intelligence_sources("hunt-two", "advisory")[0]["source_id"]
    assert first[0]["source_id"] != intelligence_sources("hunt-one", "advisory changed")[0]["source_id"]
    assert first[0]["content_sha256"] == intelligence_sources("hunt-two", "advisory")[0]["content_sha256"]
    assert intelligence_sources("hunt-one", " \n") == []
