import os
import binascii
from pqcrypto.sign import sphincs_sha2_256f_simple as sphincs

# Generate Keys: public and private key pair
def generate_keys():
    """Generates the public and private key pair using SPHINCS+."""
    pk, sk = sphincs.generate_keypair()
    return pk, sk

# Sign message using private key
def sign_message(message: bytes, secret_key: bytes):
    """Signs the message using the private key."""
    return sphincs.sign(secret_key, message)

# Verify message signature using public key
def verify_signature(message: bytes, signature: bytes, public_key: bytes):
    """Verifies the message's signature using the public key."""
    try:
        return sphincs.verify(public_key, message, signature)
    except Exception:
        return False

# Display verification results
def display_verification_results(valid, message_type="Original"):
    """Displays the verification results."""
    result = "✔ Valid" if valid else "✘ Invalid"
    print(f"{message_type} Message Verification Result: {result}")

# Save keys, signature, and message to files
def save_to_files(pk, sk, sig, msg):
    """Saves public/private keys, signature, and message to files."""
    os.makedirs(name="out", exist_ok=True)

    with open("out/public_key.bin", "wb") as f:
        f.write(pk)
    with open("out/private_key.bin", "wb") as f:
        f.write(sk)
    with open("out/signature.bin", "wb") as f:
        f.write(sig)
    with open("out/message.txt", "wb") as f:
        f.write(msg)

    print("\nAll output files saved in folder: ./out")

def main():
    """Main function that orchestrates the entire process."""
    print(" === SPHINCS+ Digital Signature System (pqcrypto) === ")

    # Step 1: Generate Keys
    pk, sk = generate_keys()

    # Original message
    msg = b"Testing SPHINCS+ quantum-resistant signature in Python."
    sig = sign_message(msg, sk)

    # Step 2: Verify Signature for the original message
    valid = verify_signature(msg, sig, pk)
    display_verification_results(valid, "Original")

    # Force invalid case: Modified message
    msg = b"Modified message!"  # This will cause the verification to fail
    valid = verify_signature(msg, sig, pk)
    display_verification_results(valid, "Modified")

    # Output the keys and signature information
    print("\nPublic Key (hex):", binascii.hexlify(pk)[:64].decode() + " ... ")
    print("Private Key (hex):", binascii.hexlify(sk)[:64].decode() + " ... ")
    print("Signature length:", len(sig), "bytes")

    # Save output files
    save_to_files(pk, sk, sig, msg)

# Run the main function
if __name__ == "__main__":
    main()
