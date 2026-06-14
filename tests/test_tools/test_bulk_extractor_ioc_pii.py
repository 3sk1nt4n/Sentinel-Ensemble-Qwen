"""bulk_extractor summary enrichment (universal, gate-safe): IP network IOCs + carved
PII (credit cards / phones) counts, CCN masked to last 4, and a deduplicated frequency-
RANKED top URLs/domains from the histogram files ("URL DAG"). Still summary-only
(record_count == 1). Synthetic feature files; no case data.
"""
from pathlib import Path

import sift_sentinel.tools.generic as gen
from sift_sentinel.tools.generic import _bulk_extractor_histogram_top, _mask_ccn


def test_histogram_top_dedups_and_ranks_by_count(tmp_path):
    h = tmp_path / "url_histogram.txt"
    h.write_text(
        "# histogram\n"
        "n=5\thttp://low.invalid/a\t(utf16=5)\n"
        "n=90\thttp://high.invalid/b\t(utf16=90)\n"
        "n=40\thttp://mid.invalid/c\n",
        encoding="utf-8",
    )
    top, distinct = _bulk_extractor_histogram_top(str(h), max_items=2)
    assert distinct == 3
    assert [t["value"] for t in top] == ["http://high.invalid/b", "http://mid.invalid/c"]
    assert top[0]["count"] == 90
    assert _bulk_extractor_histogram_top(str(tmp_path / "absent.txt"), 5) == ([], 0)


def test_mask_ccn_keeps_only_last_four():
    assert _mask_ccn("4111 1111 1111 1234") == "************1234"
    assert _mask_ccn("nope") == "****"


def test_summary_adds_ip_pii_and_url_dag_and_stays_one_record(monkeypatch, tmp_path):
    image = tmp_path / "image.dd"
    image.write_bytes(b"synthetic")
    out_dir = tmp_path / "bulk-out"
    monkeypatch.setattr(gen, "_safe_output_dir", lambda output_dir, default: str(out_dir))

    class Completed:
        returncode = 0; stdout = ""; stderr = ""

    def fake_run(cmd, *args, **kwargs):
        t = Path(cmd[2]); t.mkdir(parents=True, exist_ok=True)
        (t / "email.txt").write_text("# h\n0\ta@x.invalid\tc\n", encoding="utf-8")
        (t / "url.txt").write_text("# h\n0\thttp://x.invalid/p\tc\n", encoding="utf-8")
        (t / "domain.txt").write_text("# h\n0\tx.invalid\tc\n", encoding="utf-8")
        (t / "ip.txt").write_text(
            "# h\n10\t203.0.113.7\tstruct ip\n11\t198.51.100.9\tstruct ip\n", encoding="utf-8")
        (t / "ccn.txt").write_text("# h\n5\t4111111111111234\tc\n", encoding="utf-8")
        (t / "telephone.txt").write_text("# h\n9\t555-0100\tc\n", encoding="utf-8")
        (t / "url_histogram.txt").write_text(
            "# h\nn=99\thttp://x.invalid/p\t(utf16=99)\n", encoding="utf-8")
        return Completed()

    monkeypatch.setattr("subprocess.run", fake_run)
    result = gen.run_bulk_extractor(str(image), str(out_dir))

    assert result["record_count"] == 1 and len(result["output"]) == 1   # still summary-only
    rec = result["output"][0]
    # IP network IOCs + PII counts present
    assert rec["ips"] == 2 and rec["ccns"] == 1 and rec["telephones"] == 1
    assert "203.0.113.7" in rec["ips_sample"]
    # CCN masked -- raw card number never persisted
    assert rec["ccns_sample"] == ["************1234"]
    assert "4111111111111234" not in str(rec)
    # URL DAG: frequency-ranked top from the histogram
    assert rec["urls_top"][0] == {"value": "http://x.invalid/p", "count": 99}
    assert rec["urls_distinct"] == 1
    # carved total now folds in IPs + PII (1 email + 1 url + 1 domain + 2 ip + 1 ccn + 1 tel)
    assert rec["carved_feature_total"] == 7
