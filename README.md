# Python Rekor Verifier

A command-line tool for querying and verifying entries in a Rekor transparency log. This tool allows you to fetch log entries, verify inclusion proofs, and check the consistency of the log's Merkle tree.

## Description

This project provides a client to interact with a Rekor server (e.g., `https://rekor.sigstore.dev`).

Key features include:
- Fetching log entries by index.
- Verifying artifact signatures against public keys from log entries.
- Performing inclusion proof verification to confirm an entry is in the log.
- Verifying consistency between an old and new tree state.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/sdg8193/Software-Supply-Chain-HW-1.git
    cd python-rekor-monitor-template
    ```

2.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

The tool is operated via the command line.

### Get Latest Checkpoint

Fetch the latest signed tree head (checkpoint) from the Rekor server.
```bash
python main.py --checkpoint
```

### Verify Inclusion

Verify that an artifact is included in the log at a specific index. You need the log index and the path to the original artifact.

```bash
python main.py --inclusion <LOG_INDEX> --artifact <PATH_TO_ARTIFACT>
```

**Example:**
```bash
python main.py --inclusion 12345 --artifact ./my-file.txt
```

### Verify Consistency

Verify that a previously known checkpoint is consistent with the latest checkpoint. You need the `treeID`, `treeSize`, and `rootHash` from the old checkpoint.

```bash
python main.py --consistency --tree-id <TREE_ID> --tree-size <OLD_TREE_SIZE> --root-hash <OLD_ROOT_HASH>
```

**Example:**
```bash
python main.py --consistency --tree-id 238498... --tree-size 1000 --root-hash abcdef123...
```

### Debug Mode

For more verbose output for any command, use the `--debug` or `-d` flag.
```bash
python main.py --checkpoint --debug
```
