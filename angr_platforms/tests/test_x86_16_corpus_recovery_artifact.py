import json

from angr_platforms.X86_16.corpus_recovery_artifact import write_x86_16_cod_corpus_recovery_artifact


def test_corpus_recovery_artifact_writes_bounded_cod_batch(tmp_path):
    cod_path = tmp_path / "BATCH.COD"
    cod_path.write_text(
        "\n".join(
            [
                "_helper\tPROC NEAR",
                "\t*** 000000\te8 00 00 \t\tcall\t$+3",
                "\t*** 000003\te8 00 00 \t\tcall\t$+3",
                "\t*** 000006\te8 00 00 \t\tcall\t$+3",
                "\t*** 000009\tc3 \t\tret",
                "_helper\tENDP",
                "_guard\tPROC NEAR",
                "\t*** 000000\t3d 00 00 \t\tcmp\tax,0",
                "\t*** 000003\t74 05 \t\tje\t00000a",
                "\t*** 000005\t50 \t\tpush\tax",
                "\t*** 000006\te8 00 00 \t\tcall\t$+3",
                "\t*** 000009\t83 c4 02 \t\tadd\tsp,2",
                "\t*** 00000c\tc3 \t\tret",
                "_guard\tENDP",
            ]
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "batch.recovery.json"

    result = write_x86_16_cod_corpus_recovery_artifact(cod_path, output_path)

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert result.proc_count == 2
    assert result.write_result.row_count == 2
    assert [row["proc_name"] for row in payload["function_rows"]] == ["_guard", "_helper"]
    assert payload["confidence_status_counts"] == {
        "bounded_recovery": 1,
        "target_recovered_strong": 1,
    }
    assert payload["helper_family_rows"] == [
        {
            "count": 2,
            "family": "helper_wrapper_no_signal",
            "likely_layer": "function_effect_summary",
            "next_root_cause_file": "angr_platforms/angr_platforms/X86_16/function_effect_summary.py",
            "signal": "no_effect_signal",
        }
    ]
