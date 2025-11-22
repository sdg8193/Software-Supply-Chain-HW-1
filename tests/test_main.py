import pytest
import json
import sys
import os
from jsonschema import validate
from unittest import mock

# Import all functions from sdg8193_rekor.cli.py
from sdg8193_rekor.cli import main, get_verification_proof, get_latest_checkpoint, get_log_entry, consistency, inclusion


# --- MOCK DATA & SCHEMAS ---
CHECKPOINT_SCHEMA = {
    "type": "object",
    "properties": {
        "inactiveShards": {"type": "array", "items": {"type": "object"}},
        "rootHash": {"type": "string"},
        "signedTreeHead": {"type": "string"},
        "treeID": {"type": "string"},
        "treeSize": {"type": "integer"}
    },
    "required": ["inactiveShards", "rootHash", "signedTreeHead", "treeID", "treeSize"]
}

ACTUAL_LOG_ENTRY = {
    "inactiveShards": [
        {
            "rootHash": "4d006aa46efcb607dd51d900b1213754c50cc9251c3405c6c2561d9d6a2f3239",
            "signedTreeHead": "rekor.sigstore.dev - 3904496407287907110\n4163431\nTQBqpG78tgfdUdkAsSE3VMUMySUcNAXGwlYdnWovMjk=\n\n\u2014 rekor.sigstore.dev wNI9ajBFAiEAielNTNRyWWFvUFuCafwHkbJdLHKEoXylbcsrI9mvJO0CIFGRe6ASxGsdrapMn/oBbdImk+LY7EfqnH8awcV+qNF2\n",
            "treeID": "3904496407287907110",
            "treeSize": 4163431
        }
    ],
    "rootHash": "41edd6e8b5fdde55906614d89ebdcfe7fdfe6734994cce6bfdf05122b554f444",
    "signedTreeHead": "rekor.sigstore.dev - 1193050959916656506\n562247982\nQe3W6LX93lWQZhTYnr3P5/3+ZzSZTM5r/fBRIrVU9EQ=\n\n\u2014 rekor.sigstore.dev wNI9ajBEAiA2K870niE+/H2kdV+zsO6ZrlupSkQB1Wl+jqQNOUsa5gIgZLMLlIWDPlcvLMEOcgqvBIGEOy/fB4skHc/X44rSc7U=\n",
    "treeID": "1193050959916656506",
    "treeSize": 562247982
}

#artifact/bundle path
BUNDLE_PATH = os.path.join(os.path.dirname(__file__), "../artifact.bundle")
ARTIFACT_PATH= os.path.join(os.path.dirname(__file__), "../artifact.md")


def test_get_latest_checkpoint_success():
    checkpoint = get_latest_checkpoint(debug=False)
    validate(instance=checkpoint, schema=CHECKPOINT_SCHEMA)

def test_get_latest_checkpoint_fail(mocker, capsys):
    mock_response = mocker.Mock()
    mock_response.status_code = 404
    mock_response.text = "Not Found"
    mocker.patch("requests.get", return_value=mock_response)

    with pytest.raises(SystemExit):
        get_latest_checkpoint(debug=False)

    captured = capsys.readouterr()
    assert "Error: Status Code - 404" in captured.out
    assert "Not Found" in captured.out

def test_get_latest_checkpoint_json_fail(mocker, capsys):
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.text = "Invalid JSON"
    mock_response.json.side_effect = ValueError("No JSON object could be decoded")
    mocker.patch("requests.get", return_value=mock_response)

    with pytest.raises(SystemExit):
        get_latest_checkpoint(debug=False)

    captured = capsys.readouterr()
    assert "Error" in captured.out or "Traceback" not in captured.err

def test_get_log_entry_success():
    with open(BUNDLE_PATH, "r") as f:
        bundle = json.load(f)

    log_index = bundle["rekorBundle"]["Payload"]["logIndex"]
    log_entry = get_log_entry(log_index, debug=False)
    key = list(log_entry.keys())[0]
    assert log_entry[key]["logIndex"] == log_index
    assert "verification" in log_entry[key]
    assert "inclusionProof" in log_entry[key]["verification"]
    proof = log_entry[key]["verification"]["inclusionProof"]
    assert "logIndex" in proof
    assert "rootHash" in proof
    assert "treeSize" in proof

def test_get_log_entry_invalid_index(capsys):
    for idx in [0, -5]:
        with pytest.raises(SystemExit):
            get_log_entry(log_index=idx)
        captured = capsys.readouterr()
        assert "Log index must be an int > 0" in captured.out

def test_get_verification_proof_success():
    with open(BUNDLE_PATH, "r") as f:
        bundle = json.load(f)

    log_index = bundle["rekorBundle"]["Payload"]["logIndex"]
    proof_data = get_verification_proof(log_index, debug=False)
    assert "leaf_hash" in proof_data
    assert "index" in proof_data
    assert isinstance(proof_data["index"], int)
    assert proof_data["index"] <= proof_data["tree_size"]
    assert "root_hash" in proof_data
    assert "tree_size" in proof_data
    assert "hashes" in proof_data
    assert isinstance(proof_data["hashes"], list)

def test_get_verification_proof_cli(capsys):
    with open(BUNDLE_PATH, "r") as f:
        bundle = json.load(f)
    log_index = str(bundle["rekorBundle"]["Payload"]["logIndex"])

    original_argv = sys.argv
    try:
        sys.argv = [
            "program_name",
            "--inclusion",
            log_index,
            "--artifact",
            ARTIFACT_PATH
        ]
        main()
        captured = capsys.readouterr()
        # The actual output shows signature verification info
        assert "Signature is valid" in captured.out
        assert "Offline root hash calculation" in captured.out
    finally:
        sys.argv = original_argv

def test_consistency_direct(capsys):
    latest = ACTUAL_LOG_ENTRY
    prev_checkpoint = {
        "treeID": latest["treeID"],
        "treeSize": latest["treeSize"],
        "rootHash": latest["rootHash"]
    }
    consistency(prev_checkpoint, debug=False)
    captured = capsys.readouterr()
    assert "Consistency verification successful." in captured.out

def test_consistency_cli(capsys):
    original_argv = sys.argv
    try:
        sys.argv = [
            "program_name",
            "--consistency",
            "--tree-id", ACTUAL_LOG_ENTRY["treeID"],
            "--tree-size", str(ACTUAL_LOG_ENTRY["treeSize"]),
            "--root-hash", ACTUAL_LOG_ENTRY["rootHash"]
        ]
        main()
        captured = capsys.readouterr()
        assert "Consistency verification successful." in captured.out
    finally:
        sys.argv = original_argv


def test_consistency_invalid_checkpoint(capsys):
    original_argv = sys.argv
    try:
        sys.argv = [
            "program_name",
            "--consistency",
            "--tree-id", '119216095991665650',
            "--tree-size", str(322247982),
            "--root-hash", '41edd6e8b5fdde55906614d89ebdcfe7fdfe6734994cce6bfdf05122b554f444'
        ]
        main()
        captured = capsys.readouterr()
        assert "Failed to fetch consistency proof" in captured.out
    finally:
        sys.argv = original_argv

def test_consistency_proof_api_failure(mocker, capsys):

    prev_checkpoint = {
        "treeID": ACTUAL_LOG_ENTRY["treeID"],
        "treeSize": ACTUAL_LOG_ENTRY["treeSize"],
        "rootHash": ACTUAL_LOG_ENTRY["rootHash"]
    }

    # give it a failed return
    mock_response = mocker.Mock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mocker.patch("sdg8193_rekor.cli.requests.get", return_value=mock_response)

    # get system exit
    with pytest.raises(SystemExit):
        consistency(prev_checkpoint, debug=False)

    captured = capsys.readouterr()
    assert "Error: Status Code - 500" in captured.out
    assert "Internal Server Error" in captured.out


def test_consistency_verification_error(mocker, capsys):
    # fail on hash
    prev_checkpoint = {
        "treeID": ACTUAL_LOG_ENTRY["treeID"],
        "treeSize": ACTUAL_LOG_ENTRY["treeSize"] - 1,  
        "rootHash": "deadbeef"  
    }

    mocker.patch("sdg8193_rekor.cli.get_latest_checkpoint", return_value=ACTUAL_LOG_ENTRY)
    consistency(prev_checkpoint, debug=False)

    captured = capsys.readouterr()
    assert "Error: Calculated root" in captured.out
    assert "does not match expected root" in captured.out

def test_inclusion_file_not_found(mocker, capsys):
    
    fake_path = "/tmp/non_existent_artifact.bundle"
    inclusion(log_index=1,artifact_filepath=fake_path, debug=False)

    captured = capsys.readouterr()
    assert "Please include valid filepath" in captured.out

def test_failed_verification(capsys):
    with open(BUNDLE_PATH, "r") as f:
        bundle = json.load(f)
    log_index = str(bundle["rekorBundle"]["Payload"]["logIndex"])

    original_argv = sys.argv
    try:
        sys.argv = [
            "program_name",
            "--inclusion",
            log_index,
            "--artifact",
            BUNDLE_PATH
        ]
        main()
        captured = capsys.readouterr()


        assert "Signature is invalid" in captured.out
        assert "Signature verification failed" in captured.out
    finally:
        sys.argv = original_argv


def test_inclusion_invalid_log_index(capsys):
    inclusion(-1, "/tmp/fakefile")
    captured = capsys.readouterr()
    assert "Log index must be an int > 0" in captured.out


def test_get_log_entry_http_error(mocker):
    mock_response = mocker.Mock()
    mock_response.status_code = 500
    mocker.patch("sdg8193_rekor.cli.requests.get", return_value=mock_response)
    with pytest.raises(SystemExit):
        get_log_entry(1)


def test_get_verification_proof_debug(mocker, capsys):
    mock_entry = {
        "1": {
            "body": b"{}",
            "verification": {"inclusionProof": {"logIndex": 1, "rootHash": "root", "treeSize": 1, "hashes": []}}
        }
    }
    mocker.patch("sdg8193_rekor.cli.get_log_entry", return_value=mock_entry)
    blob = get_verification_proof(1, debug=True)
    captured = capsys.readouterr()
    assert "get_verification_proof" in captured.out
    assert blob["leaf_hash"]

def test_consistency_verify_exceptions(mocker, capsys):
    prev = ACTUAL_LOG_ENTRY
    mocker.patch("sdg8193_rekor.cli.get_latest_checkpoint", return_value=ACTUAL_LOG_ENTRY)
    mocker.patch("sdg8193_rekor.cli.requests.get", return_value=mock.Mock(status_code=200, json=lambda: {"hashes":[]}))

    mocker.patch("sdg8193_rekor.cli.verify_consistency", side_effect=ValueError("bad"))
    consistency(prev)
    captured = capsys.readouterr()
    assert "Consistency verification failed" in captured.out


def test_main_missing_args(mocker, capsys):
    sys.argv = ["prog", "--consistency"]
    main()
    captured = capsys.readouterr()
    assert "please specify tree id" in captured.out.lower()