"""
Rekor Verifier Client.

This module provides command-line functions for querying the Rekor transparency
log and verifying the inclusion and consistency of log entries and checkpoints
using Merkle tree proofs.
"""

import argparse
import json
import base64
import os
import sys
import requests
from util import extract_public_key, verify_artifact_signature
from merkle_proof import (
    DEFAULT_HASHER,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
    RootMismatchError,
)

SERVER = "https://rekor.sigstore.dev"


def get_log_entry(log_index, debug=False):
    """
    Fetches a specific log entry from the Rekor server by its log index.

    Parameters
    ----------
    log_index : int
        The index of the log entry to retrieve (must be > 0).
    debug : bool, optional
        If True, prints the raw HTTP response (default is False).

    Returns
    -------
    dict
        The JSON response containing the log entry data.

    Raises
    ------
    SystemExit
        If the log index is invalid or the HTTP request fails.
    """
    # verify that log index value is sane
    if not (isinstance(log_index, int) and log_index > 0):
        print("Log index must be an int > 0")
        sys.exit()

    url = f"{SERVER}/api/v1/log/entries?logIndex={log_index}"
    response = requests.get(url,timeout=10)

    if response.status_code != 200:
        print(
            f"Error fetching log entry {log_index}: Status Code - {response.status_code}"
        )
        sys.exit()

    if debug:
        print(f"get_log_entry:\n {response}")
    return response.json()


def get_verification_proof(log_index, debug=False):
    """
    Extracts the data needed for offline Merkle tree inclusion verification.

    Parameters
    ----------
    log_index : int
        The index of the log entry to retrieve proof data for.
    debug : bool, optional
        If True, prints debug information (default is False).

    Returns
    -------
    dict
        A dictionary containing 'leaf_hash', 'index', 'root_hash', 'tree_size',
    """

    if debug:
        print(f"get_verification_proof:\n{log_index}")
    # verify that log index value is sane
    entry = get_log_entry(log_index, debug)
    key = list(entry.keys())[0]
    entry_data = entry[key]

    inclusion_proof = entry_data["verification"]["inclusionProof"]

    leaf_hash = compute_leaf_hash(entry_data.get("body"))
    blob = {
        "leaf_hash": leaf_hash,
        "index": inclusion_proof["logIndex"],
        "root_hash": inclusion_proof["rootHash"],
        "tree_size": inclusion_proof["treeSize"],
        "hashes": inclusion_proof["hashes"],
    }

    return blob


def inclusion(log_index, artifact_filepath, debug=False):
    """
    Performs inclusion verification for an artifact.
    Parameters
    ----------
    log_index : int
        The index of the log entry to verify.
    artifact_filepath : str
        The local path to the original artifact file.
    debug : bool, optional
        If True, prints detailed debug information (default is False).
    """
    # verify that log index and artifact filepath values are sane
    if not (isinstance(log_index, int) and log_index > 0):
        print("Log index must be an int > 0")
        return
    # test file path and read
    if artifact_filepath is None or not os.path.isfile(artifact_filepath):
        print("Please include valid filepath")
        return

    try:
        with open(artifact_filepath, "rb") as file_path:
            file_path.read()
    except FileNotFoundError:
        print(f"File Not Found: {artifact_filepath}")
        sys.exit()
    except (PermissionError, IOError, OSError) as error_msg:
        print(f"Failed to read file: {artifact_filepath}, error {error_msg}")
        sys.exit(1)

    # get log
    transaction_log = get_log_entry(log_index, debug)
    key = list(transaction_log.keys())[0]

    # get body and decode
    body = transaction_log.get(key).get("body")

    decoded_data = json.loads(base64.b64decode(body).decode("utf-8"))
    encoded_cert = decoded_data["spec"]["signature"]["publicKey"]["content"]
    decoded_cert = base64.b64decode(encoded_cert)

    # extract_public_key(certificate)
    public_key = extract_public_key(decoded_cert)

    # extract_signature
    signature = base64.b64decode(decoded_data["spec"]["signature"]["content"])
    try:
        verify_artifact_signature(signature, public_key, artifact_filepath)
        print("Signature is valid.")
    except (ValueError, RuntimeError) as function_error:
        print("Signature verification failed:", function_error)
        if debug:
            print(f"{function_error}")

    proof_data = get_verification_proof(log_index)
    try:
        verify_inclusion(
            DEFAULT_HASHER,
            proof_data,
            debug=debug,
        )
        print("Offline root hash calculation for inclusion verified.")
    except (ValueError, TypeError) as function_error:
        print(f"Inclusion proof FAILED due to verification error:\n{function_error}")
        return


def get_latest_checkpoint(debug=False):
    """
    Fetches the latest tree checkpoint from the Rekor server.

    Parameters
    ----------
    debug : bool, optional
        If True, prints the raw HTTP response text (default is False).

    Returns
    -------
    dict
        The JSON response containing the latest checkpoint details, including
        'rootHash', 'treeSize', and 'treeID'.

    Raises
    ------
    SystemExit
        If the HTTP request fails.
    """
    url = f"{SERVER}/api/v1/log"
    response = requests.get(url,timeout=10)
    if debug:
        print(f"get_latest_checkpoint:\n {response.text}")
    if response.status_code == 200:
        return response.json()

    print(f"Error: Status Code - {response.status_code}")
    print(f"Response: {response.text}")
    sys.exit()


def consistency(prev_checkpoint, debug=False):
    """
    Verifies the consistency between a previous checkpoint and the latest checkpoint.

    Parameters
    ----------
    prev_checkpoint : dict
        The older checkpoint, must contain 'treeID', 'treeSize', and 'rootHash'.
    debug : bool, optional
        If True, prints debug information, including the proof data (default is False).

    Raises
    ------
    ValueError
        If the consistency proof or its components are invalid.
    RootMismatchError
        If the calculated root for either tree does not match the provided root.
    """
    # verify that prev checkpoint is not empty
    if not all(prev_checkpoint.values()):
        print("prev_checkpoint contains empty values")
        if debug:
            print(prev_checkpoint)
        return

    latest = get_latest_checkpoint()
    tree_id = prev_checkpoint["treeID"]
    old_size = prev_checkpoint["treeSize"]
    new_size = latest["treeSize"]

    proof_url = (
        f"{SERVER}/api/v1/log/proof?"
        f"firstSize={old_size}"
        f"&lastSize={new_size}"
        f"&treeID={tree_id}"
    )

    response = requests.get(proof_url,timeout=10)
    if response.status_code != 200:
        print(f"Failed to fetch consistency proof: {response.status_code}")
        print(response.text)
        return

    proof_data = response.json()
    proof_hashes = proof_data.get("hashes")

    if debug:
        print(proof_data)

    try:
        verify_consistency(
            DEFAULT_HASHER,
            old_checkpoint=prev_checkpoint,
            new_checkpoint=latest,
            proof=proof_hashes,
        )
        print("Consistency verification successful.")
    except ValueError as function_error:
        print(f"Consistency verification failed: {function_error}")
    except RootMismatchError as function_error:
        print(f"Error: {function_error}")


def main():
    """
    The main entry point for the Rekor Verifier command-line application.
    """
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )  # Default false
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
