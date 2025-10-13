"""
Implements Merkle tree hashing, verification,
and proof chaining logic for transparency logs.
"""

import hashlib
import binascii
import base64

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    """
    Implements the hash functions for the Merkle tree.
    """

    def __init__(self, hash_func=hashlib.sha256):
        """
        Initializes the Hasher with a specified hash function.

        Parameters
        ----------
        hash_func : callable, optional
            The hashing algorithm to use (default is hashlib.sha256).
        """
        self.hash_func = hash_func

    def new(self):
        """
        Creates a new, empty hash calculation object.

        Returns
        -------
        hashlib._Hash
            A new instance of the configured hash function.
        """
        return self.hash_func()

    def empty_root(self):
        """
        Calculates the hash for an empty Merkle tree.

        Returns
        -------
        bytes
            The hash of the empty tree (an empty byte string digested).
        """
        return self.new().digest()

    def hash_leaf(self, leaf):
        """
        Calculates the hash of a leaf node.

        Parameters
        ----------
        leaf : bytes
            The raw data of the leaf entry.

        Returns
        -------
        bytes
            The leaf hash.
        """
        hash_calc = self.new()
        hash_calc.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        hash_calc.update(leaf)
        return hash_calc.digest()

    def hash_children(self, left_hash, right_hash):
        """
        Calculates the hash of an internal node.

        Parameters
        ----------
        left_hash : bytes
            The hash of the left child.
        right_hash : bytes
            The hash of the right child.

        Returns
        -------
        bytes
            The hash.
        """
        hash_calc = self.new()
        hash_bytes = bytes([RFC6962_NODE_HASH_PREFIX]) + left_hash + right_hash
        hash_calc.update(hash_bytes)
        return hash_calc.digest()

    def size(self):
        """
        Returns the output size of the configured hash function in bytes.

        Returns
        -------
        int
            The digest size in bytes.
        """
        return self.new().digest_size


# DefaultHasher is a SHA256 based LogHasher
DEFAULT_HASHER = Hasher(hashlib.sha256)


def _extract_inputs(old_checkpoint, new_checkpoint, proof):
    """
    Extracts and validates input data from checkpoint and proof objects.

    Converts hex-encoded root hashes and proof components to byte arrays.

    Parameters
    ----------
    old_checkpoint : dict
        The starting checkpoint with 'treeSize' and 'rootHash'.
    new_checkpoint : dict
        The ending checkpoint with 'treeSize' and 'rootHash'.
    proof : list of str
        The consistency proof components as a list of hex strings.

    Returns
    -------
    tuple
        (size1, size2, root1_bytes, root2_bytes, bytearray_proof)

    Raises
    ------
    ValueError
        If size2 is less than size1.
    """
    size1 = old_checkpoint["treeSize"]
    size2 = new_checkpoint["treeSize"]

    if size2 < size1:
        raise ValueError(f"size2 ({size2}) < size1 ({size1})")

    root1 = bytes.fromhex(old_checkpoint["rootHash"])
    root2 = bytes.fromhex(new_checkpoint["rootHash"])
    bytearray_proof = [bytes.fromhex(elem) for elem in proof]

    return size1, size2, root1, root2, bytearray_proof


def _validate_proof_sizes(size1, size2, bytearray_proof, root1, root2):
    """
    Validates the consistency proof based on tree sizes (size1, size2).

    Handles the edge cases where size1 == size2 or size1 == 0.

    Parameters
    ----------
    size1 : int
        The size of the older tree.
    size2 : int
        The size of the newer tree.
    bytearray_proof : list of bytes
        The list of hash parts in the proof.
    root1 : bytes
        The root hash of the older tree.
    root2 : bytes
        The root hash of the newer tree.

    Returns
    -------
    bool
        True if the proof is valid (e.g., size1==size2 or size1==0)
        and no further chain verification is needed. False otherwise.

    Raises
    ------
    ValueError
        If proof is non-empty when size1=size2, or proof is empty when expected.
    """
    if size1 == size2:
        if bytearray_proof:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(root1, root2)
        return True
    if size1 == 0:
        if bytearray_proof:
            raise ValueError(
                "expected empty bytearray_proof,"
                "but got {len(bytearray_proof)} components"
            )
        return True
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")
    return False


def verify_consistency(hasher, old_checkpoint, new_checkpoint, proof):
    """
    Verifies that the new_checkpoint is a consistent extension of the
    old_checkpoint using a consistency proof.

    The consistency proof demonstrates that the elements in the older tree
    are an initial contiguous subset of the elements in the newer tree.

    Parameters
    ----------
    hasher : Hasher
        The hash function object used by the tree.
    old_checkpoint : dict
        The starting (smaller) checkpoint.
    new_checkpoint : dict
        The ending (larger) checkpoint.
    proof : list of str
        The list of hex-encoded hash components for the consistency proof.

    Raises
    ------
    ValueError
        If the proof size is incorrect or verification fails.
    RootMismatchError
        If the calculated root for either tree does not match the provided root.
    """
    # inputs - [size1, size2, root1, root2, bytearray_proof]
    inputs = _extract_inputs(old_checkpoint, new_checkpoint, proof)
    if _validate_proof_sizes(inputs[0], inputs[1], inputs[4], inputs[2], inputs[3]):
        return

    inner, border = decomp_incl_proof(inputs[0] - 1, inputs[1])
    shift = (inputs[0] & -inputs[0]).bit_length() - 1
    inner -= shift

    if inputs[0] == 1 << shift:
        seed, start = inputs[2], 0
    else:
        seed, start = inputs[4][0], 1

    if len(inputs[4]) != start + inner + border:
        raise ValueError(
            f"wrong bytearray_proof size {len(inputs[4])}, want {start + inner + border}"
        )

    bytearray_proof = inputs[4][start:]

    mask = (inputs[0] - 1) >> shift
    hash1 = chain_inner_right(hasher, seed, bytearray_proof[:inner], mask)
    hash1 = chain_border_right(hasher, hash1, bytearray_proof[inner:])
    verify_match(hash1, inputs[2])

    hash2 = chain_inner(hasher, seed, bytearray_proof[:inner], mask)
    hash2 = chain_border_right(hasher, hash2, bytearray_proof[inner:])
    verify_match(hash2, inputs[3])


def verify_match(calculated, expected):
    """
    Checks if a calculated hash matches an expected hash.

    Parameters
    ----------
    calculated : bytes
        The computed root hash.
    expected : bytes
        The root hash provided in the checkpoint.

    Raises
    ------
    RootMismatchError
        If the two hashes do not match.
    """
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index, size):
    """
    Calculates the sizes of the 'inner' and 'border' segments of an
    inclusion or consistency proof chain based on tree properties.

    Parameters
    ----------
    index : int
        The 0-based index (for inclusion) or the old size - 1 (for consistency).
    size : int
        The size of the tree.

    Returns
    -------
    tuple
        (inner_size, border_size)
    """
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index, size):
    """
    Calculates the size of the inner part of a proof chain.

    Parameters
    ----------
    index : int
        The index into the tree (0-based).
    size : int
        The size of the tree.

    Returns
    -------
    int
        The size of the inner proof segment.
    """
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher, seed, proof, index):
    """
    Chains the hash components in the inner part of a proof.

    Parameters
    ----------
    hasher : Hasher
        The hash function object.
    seed : bytes
        The starting hash value.
    proof : list of bytes
        The inner segment of the proof hash components.
    index : int
        The index used to determine which side to hash on.

    Returns
    -------
    bytes
        The resulting hash after chaining the inner proof segment.
    """
    for i, hash_component in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, hash_component)
        else:
            seed = hasher.hash_children(hash_component, seed)
    return seed


def chain_inner_right(hasher, seed, proof, index):
    """
    Chains the hash components in the inner right part of a consistency proof.

    Parameters
    ----------
    hasher : Hasher
        The hash function object.
    seed : bytes
        The starting hash value.
    proof : list of bytes
        The inner segment of the proof hash components.
    index : int
        The index used to determine which components to apply.

    Returns
    -------
    bytes
        The resulting hash after chaining the inner right proof segment.
    """
    for i, hash_component in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(hash_component, seed)
    return seed


def chain_border_right(hasher, seed, proof):
    """
    Chains the hash components in the border part of a proof.

    Parameters
    ----------
    hasher : Hasher
        The hash function object.
    seed : bytes
        The starting hash value.
    proof : list of bytes
        The border segment of the proof hash components.

    Returns
    -------
    bytes
        The resulting hash after chaining the border proof segment.
    """
    for hash_component in proof:
        seed = hasher.hash_children(hash_component, seed)
    return seed


class RootMismatchError(Exception):
    """
    Exception raised when a calculated Merkle root hash does not match
    the expected root hash during verification.
    """
    def __init__(self, expected_root, calculated_root):
        """
        Initializes the exception with the expected and calculated root hashes.

        Parameters
        ----------
        expected_root : bytes
            The root hash that was expected.
        calculated_root : bytes
            The root hash that was computed.
        """

        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

        message = (
            f"Calculated root:\n{self.calculated_root}\n does not match "
            f"expected root:\n{self.expected_root}"
        )
        super().__init__(message)


def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
    """
    Calculates the root hash of a Merkle tree given a leaf, its index, and an
    inclusion proof.

    Parameters
    ----------
    hasher : Hasher
        The hash function object.
    index : int
        The 0-based index of the leaf in the tree.
    size : int
        The size of the tree.
    leaf_hash : bytes
        The domain-separated hash of the leaf entry.
    proof : list of bytes
        The list of hash components for the inclusion proof.

    Returns
    -------
    bytes
        The calculated root hash of the tree.

    Raises
    ------
    ValueError
        If the index is out of bounds or the proof size is incorrect.
    """
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(
            f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}"
        )

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(hasher, proof_data, debug=False):
    """
    Verifies a full inclusion proof against a given root hash.

    Parameters
    ----------
    hasher : Hasher
        The hash function object.
    proof_data : dict
        A dictionary containing 'index', 'tree_size', 'leaf_hash',
        'hashes' (proof components), and 'root_hash'.
    debug : bool, optional
        If True, prints the calculated and given root hashes (default is False).

    Raises
    ------
    RootMismatchError
        If the calculated root does not match the expected root.
    """
    index = proof_data["index"]
    size = proof_data["tree_size"]
    leaf_hash = proof_data["leaf_hash"]
    proof = proof_data["hashes"]
    root = proof_data["root_hash"]

    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    bytearray_root = bytes.fromhex(root)
    bytearray_leaf = bytes.fromhex(leaf_hash)
    calc_root = root_from_inclusion_proof(
        hasher, index, size, bytearray_leaf, bytearray_proof
    )
    verify_match(calc_root, bytearray_root)
    if debug:
        print("Calculated root hash", calc_root.hex())
        print("Given root hash", bytearray_root.hex())


# requires entry["body"] output for a log entry
# returns the leaf hash according to the rfc 6962 spec
def compute_leaf_hash(body):
    """
    Calculates the hex-encoded leaf hash for a log entry body.
    Parameters
    ----------
    body : str
        The base64-encoded body output from a log entry.

    Returns
    -------
    str
        The hex-encoded, domain-separated leaf hash.
    """
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    hash_calc = hashlib.sha256()
    # write the leaf hash prefix
    hash_calc.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    hash_calc.update(entry_bytes)

    # return the computed hash
    return hash_calc.hexdigest()
