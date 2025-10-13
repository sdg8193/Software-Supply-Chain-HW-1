import hashlib
import binascii
import base64

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    def __init__(self, hash_func=hashlib.sha256):
        self.hash_func = hash_func

    def new(self):
        return self.hash_func()

    def empty_root(self):
        return self.new().digest()

    def hash_leaf(self, leaf):
        hash_calc = self.new()
        hash_calc.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        hash_calc.update(leaf)
        return hash_calc.digest()

    def hash_children(self, left_hash, right_hash):
        hash_calc = self.new()
        hash_bytes = bytes([RFC6962_NODE_HASH_PREFIX]) + left_hash + right_hash
        hash_calc.update(hash_bytes)
        return hash_calc.digest()

    def size(self):
        return self.new().digest_size


# DefaultHasher is a SHA256 based LogHasher
DEFAULT_HASHER = Hasher(hashlib.sha256)


def _extract_inputs(old_checkpoint, new_checkpoint, proof):
    size1 = old_checkpoint["treeSize"]
    size2 = new_checkpoint["treeSize"]

    if size2 < size1:
        raise ValueError(f"size2 ({size2}) < size1 ({size1})")

    root1 = bytes.fromhex(old_checkpoint["rootHash"])
    root2 = bytes.fromhex(new_checkpoint["rootHash"])
    bytearray_proof = [bytes.fromhex(elem) for elem in proof]

    return size1, size2, root1, root2, bytearray_proof


def _validate_proof_sizes(size1, size2, bytearray_proof, root1, root2):
    if size1 == size2:
        if bytearray_proof:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(root1, root2)
        return True
    if size1 == 0:
        if bytearray_proof:
            raise ValueError("expected empty bytearray_proof,"
                             "but got {len(bytearray_proof)} components")
        return True
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")
    return False


def verify_consistency(hasher, old_checkpoint, new_checkpoint, proof):
    #inputs - [size1, size2, root1, root2, bytearray_proof] 
    inputs = (
        _extract_inputs(old_checkpoint, new_checkpoint, proof)
    )
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
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index, size):
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index, size):
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher, seed, proof, index):
    for i, hash_component in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, hash_component)
        else:
            seed = hasher.hash_children(hash_component, seed)
    return seed


def chain_inner_right(hasher, seed, proof, index):
    for i, hash_component in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(hash_component, seed)
    return seed


def chain_border_right(hasher, seed, proof):
    for hash_component in proof:
        seed = hasher.hash_children(hash_component, seed)
    return seed


class RootMismatchError(Exception):
    def __init__(self, expected_root, calculated_root):
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

        message = (
            f"Calculated root:\n{self.calculated_root}\n does not match "
            f"expected root:\n{self.expected_root}"
        )
        super().__init__(message)

def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
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
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    hash_calc = hashlib.sha256()
    # write the leaf hash prefix
    hash_calc.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    hash_calc.update(entry_bytes)

    # return the computed hash
    return hash_calc.hexdigest()
