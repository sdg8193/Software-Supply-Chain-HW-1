# Python Rekor Verifier 
![CI](https://github.com/sdg8193/Software-Supply-Chain-HW-1/actions/workflows/ci.yml/badge.svg)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/{owner}/{repo}/badge)](https://scorecard.dev/viewer/?uri=github.com/{owner}/{repo})
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11564/badge)](https://www.bestpractices.dev/projects/11564

A command-line tool for querying and verifying entries in a Rekor transparency log. This tool allows you to fetch log entries, verify inclusion proofs, and check the consistency of the log's Merkle tree.

## Description

This project provides a client to interact with a Rekor server (e.g., `https://rekor.sigstore.dev`).

Key features include:
- Fetching log entries by index.
- Verifying artifact signatures against public keys from log entries.
- Performing inclusion proof verification to confirm an entry is in the log.
- Verifying consistency between an old and new tree state.

## Installation

You can either install the package globally from PyPI or run it from source using Poetry.

### Option 1: Install from PyPI (Recommended)

```bash
pip install sdg8193_rekor
```

This installs a global command:

```
sdg8193_rekor
```

### Option 2: Run from Source (Development Mode)

Clone the repository:

```bash
git clone https://github.com/sdg8193/Software-Supply-Chain-HW-1.git
cd Software-Supply-Chain-HW-1
```

Install dependencies using Poetry:

```bash
pip install poetry
poetry install
```

## Usage

You can run the tool either globally (PyPI install) or via Poetry (source version).

### Get Latest Checkpoint

Fetch the latest signed tree head (checkpoint) from the Rekor server.

**PyPI (Global):**
```bash
sdg8193_rekor --checkpoint
```

**Poetry (Source):**
```bash
poetry run sdg8193_rekor --checkpoint
```

### Verify Inclusion

Verify that an artifact is included in the log at a specific index.

**PyPI (Global):**
```bash
sdg8193_rekor --inclusion <LOG_INDEX> --artifact <PATH_TO_ARTIFACT>
```

**Poetry (Source):**
```bash
poetry run sdg8193_rekor --inclusion <LOG_INDEX> --artifact <PATH_TO_ARTIFACT>
```

**Example:**
```bash
sdg8193_rekor --inclusion 12345 --artifact ./my-file.txt
```

### Verify Consistency

Verify that a previously known checkpoint is consistent with the newest checkpoint.

**PyPI (Global):**
```bash
sdg8193_rekor --consistency --tree-id <TREE_ID> --tree-size <OLD_TREE_SIZE> --root-hash <OLD_ROOT_HASH>
```

**Poetry (Source):**
```bash
poetry run sdg8193_rekor --consistency --tree-id <TREE_ID> --tree-size <OLD_TREE_SIZE> --root-hash <OLD_ROOT_HASH>
```

**Example:**
```bash
sdg8193_rekor --consistency --tree-id 238498... --tree-size 1000 --root-hash abcdef123...
```

### Debug Mode

For verbose internal logs during any operation, use:

**PyPI (Global):**
```bash
sdg8193_rekor --checkpoint --debug
```

**Poetry (Source):**
```bash
poetry run sdg8193_rekor --checkpoint --debug
```