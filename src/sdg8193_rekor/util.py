"""
Utility functions for cryptographic operations related to artifact signature
verification.
"""

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature


# extracts and returns public key from a given cert (in pem format)
def extract_public_key(cert):
    """
    Extracts the public key from an X.509 certificate and returns it in PEM format.

    Parameters
    ----------
    cert : bytes
        The X.509 certificate data in PEM format.

    Returns
    -------
    bytes
        The extracted public key encoded in PEM format
        (SubjectPublicKeyInfo structure).
    """
    # read the certificate
    #    with open("cert.pem", "rb") as cert_file:
    #        cert_data = cert_file.read()

    # load the certificate
    certificate = x509.load_pem_x509_certificate(cert, default_backend())

    # extract the public key
    public_key = certificate.public_key()

    # save the public key to a PEM file
    #    with open("cert_public.pem", "wb") as pub_key_file:
    #        pub_key_file.write(public_key.public_bytes(
    #            encoding=serialization.Encoding.PEM,
    #            format=serialization.PublicFormat.SubjectPublicKeyInfo
    #        ))
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return pem_public_key


def verify_artifact_signature(signature, public_key, artifact_filename):
    """
    Verifies the digital signature of an artifact file using a public key.

    Parameters
    ----------
    signature : bytes
        The raw digital signature bytes.
    public_key : bytes
        The public key in PEM format used for verification.
    artifact_filename : str
        The filepath to the original artifact data whose signature is being verified.

    Raises
    ------
    ValueError
        If the signature is invalid (does not match the data and public key).
    RuntimeError
        If an unexpected exception occurs during the verification process
        (e.g., file reading error).
    """
    # load the public key
    # with open("cert_public.pem", "rb") as pub_key_file:
    #    public_key = load_pem_public_key(pub_key_file.read())

    # load the signature
    #    with open("hello.sig", "rb") as sig_file:
    #        signature = sig_file.read()

    public_key = load_pem_public_key(public_key, backend=default_backend())

    # load the data to be verified
    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    # verify the signature
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("Signature is invalid")
        raise ValueError("Signature verification failed")
    except Exception as artifact_exception:
        print("Exception in verifying artifact signature:", artifact_exception)
        raise RuntimeError(
            f"Exception in verifying artifact signature: {artifact_exception}"
        )
