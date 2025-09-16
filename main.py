import argparse
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

import requests
import json
import base64
import os
SERVER = "https://rekor.sigstore.dev"

def get_log_entry(log_index, debug=False):
    # verify that log index value is sane
    if not (isinstance(log_index,int) and log_index >0):
        print("Log index must be an int > 0")
        return
    
    url = f"{SERVER}/api/v1/log/entries?logIndex={log_index}"
    response = requests.get(url)

    if debug:
        print(f"get_log_entry:\n {response}")
    return response.json()

def get_verification_proof(log_index, debug=False):
    if debug:
        print(f"get_verification_proof:\n{log_index}")
    # verify that log index value is sane
    entry = get_log_entry(log_index, debug)
    key = list(entry.keys())[0]
    entry_data = entry[key]

    iP = entry_data['verification']['inclusionProof']

    lh = json.loads(base64.b64decode(entry_data['body']).decode())['spec']['data']['hash']['value']
    blob = {
        "leaf_hash": lh,
        "index": iP['logIndex'],
        "root_hash": iP['rootHash'],
        "tree_size": iP['treeSize'],
        "hashes": iP['hashes']
    }

    return blob

def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane
    if not (isinstance(log_index,int) and log_index >0):
        print("Log index must be an int > 0")
        return
    #test file path and read
    if artifact_filepath is None or not (os.path.isfile(artifact_filepath)):
        print("Please include valid filepath")
        return
    f = open(artifact_filepath,"rb")
    try:
        filebytes = f.read()
    except:
        print(f"Failed to read file: {artifact_filepath}")

    #get log
    transaction_log = get_log_entry(log_index)
    key = list(transaction_log.keys())[0]

    #get body and decode
    body = transaction_log.get(key).get('body')
    
    decoded_data = json.loads(base64.b64decode(body).decode('utf-8'))
    encoded_cert = decoded_data['spec']['signature']['publicKey']['content']
    decoded_cert = base64.b64decode(encoded_cert)

    # extract_public_key(certificate)
    public_key = extract_public_key(decoded_cert)

    #extract_signature
    signature = base64.b64decode(decoded_data['spec']['signature']['content'])
    try:
        verify_artifact_signature(signature, public_key, artifact_filepath)
    except:
        print("Failed: Returning")
        return()
    
    ##comeback
    info = get_verification_proof(log_index)
    print(info.keys())
    verify_inclusion(DefaultHasher, info.get('index'), info.get('tree_size'), info.get('leaf_hash'), info.get('hashes'), info.get('root_hash'))
    pass

def get_latest_checkpoint(debug=False):
    url = f"{SERVER}/api/v1/log"
    response = requests.get(url)
    if debug:
        print(f"get_latest_checkpoint:\n {response.text}")
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Status Code - {response.status_code}")
        print(f"Response: {response.text}")
        return None
    return response

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    # get_latest_checkpoint()
    pass

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
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
