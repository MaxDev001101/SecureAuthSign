import argparse, os, json
from cryptography.hazmat.primitives import serialization
from crypto_core.key_manager import KeyPair
from crypto_core.certificate import Certificate
from crypto_core.auth import Authenticator
from crypto_core.document import DocumentProcessor, SecureTransmitter

DATA = "data"

def init_ca():
    os.makedirs(f"{DATA}/RootCA", exist_ok=True)
    kp = KeyPair("RootCA")
    with open(f"{DATA}/RootCA/private.pem", "wb") as f: f.write(kp.get_private_pem())
    with open(f"{DATA}/RootCA/public.pem", "wb") as f: f.write(kp.get_public_pem())
    cert = Certificate("RootCA", kp.public_key, kp.private_key, is_ca=True)
    with open(f"{DATA}/RootCA/certificate.pem", "wb") as f: f.write(cert.get_pem())
    print("[✓] Root CA initialized.")

def register(user, algo="RSA-2048"):
    if not os.path.exists(f"{DATA}/RootCA/private.pem"):
        print("[!] Run 'init-ca' first."); return
    os.makedirs(f"{DATA}/{user}", exist_ok=True)
    kp = KeyPair(user, algo)
    with open(f"{DATA}/{user}/private.pem", "wb") as f: f.write(kp.get_private_pem())
    with open(f"{DATA}/{user}/public.pem", "wb") as f: f.write(kp.get_public_pem())
    
    with open(f"{DATA}/RootCA/private.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    cert = Certificate(user, kp.public_key, ca_key, issuer_name="RootCA")
    with open(f"{DATA}/{user}/certificate.pem", "wb") as f: f.write(cert.get_pem())
    print(f"[✓] {user} registered & certified.")

def auth(user):
    if not os.path.exists(f"{DATA}/{user}/private.pem"):
        print(f"[!] User {user} not found."); return
    priv = serialization.load_pem_private_key(open(f"{DATA}/{user}/private.pem","rb").read(), password=None)
    nonce = Authenticator.generate_nonce()
    sig = Authenticator.sign_nonce(priv, nonce)
    pub = serialization.load_pem_public_key(open(f"{DATA}/{user}/public.pem","rb").read())
    print(f"[✓] {user} authenticated" if Authenticator.verify_nonce(pub, nonce, sig) else f"[✗] {user} failed auth")

def sign_doc(user, doc_path):
    if not os.path.exists(f"{DATA}/{user}/private.pem"):
        print(f"[!] User {user} not found."); return
    with open(doc_path, "rb") as f: doc = f.read()
    priv = serialization.load_pem_private_key(open(f"{DATA}/{user}/private.pem","rb").read(), password=None)
    sig = DocumentProcessor.sign_document(priv, doc)
    sig_path = f"{doc_path}.sig"
    with open(sig_path, "wb") as f: f.write(sig)
    print(f"[✓] Signed: {sig_path}")

def verify_doc(user, doc_path):
    with open(doc_path, "rb") as f: doc = f.read()
    sig_path = f"{doc_path}.sig"
    if not os.path.exists(sig_path): print("[!] No signature file."); return
    with open(sig_path, "rb") as f: sig = f.read()
    pub = serialization.load_pem_public_key(open(f"{DATA}/{user}/public.pem","rb").read())
    print("[✓] Verified" if DocumentProcessor.verify_document(pub, doc, sig) else "[✗] Verification Failed")

def encrypt_file(sender, receiver, doc_path):
    if not os.path.exists(f"{DATA}/{receiver}/public.pem"):
        print(f"[!] Recipient {receiver} public key not found."); return
    with open(doc_path, "rb") as f: doc = f.read()
    rec_pub = serialization.load_pem_public_key(open(f"{DATA}/{receiver}/public.pem","rb").read())
    pkg = SecureTransmitter.encrypt_document(doc, rec_pub)
    enc_path = f"{doc_path}.enc"
    with open(enc_path, "w") as f: json.dump(pkg, f)
    print(f"[✓] Encrypted for {receiver}: {enc_path}")

def decrypt_file(receiver, enc_path):
    if not os.path.exists(f"{DATA}/{receiver}/private.pem"):
        print(f"[!] Recipient {receiver} private key not found."); return
    with open(enc_path) as f: pkg = json.load(f)
    priv = serialization.load_pem_private_key(open(f"{DATA}/{receiver}/private.pem","rb").read(), password=None)
    doc = SecureTransmitter.decrypt_document(pkg, priv)
    out_path = enc_path.replace(".enc", ".dec")
    with open(out_path, "wb") as f: f.write(doc)
    print(f"[✓] Decrypted: {out_path}")

def main():
    p = argparse.ArgumentParser(prog="SecureAuthSign")
    p.add_argument("cmd", choices=["init-ca","register","auth","sign","verify","encrypt","decrypt"])
    p.add_argument("--user", help="User ID")
    p.add_argument("--algo", default="RSA-2048", choices=["RSA-2048","ECC-P256"])
    p.add_argument("--file", help="Path to file")
    p.add_argument("--target", help="Recipient user ID (for encrypt)")
    args = p.parse_args()

    if args.cmd == "init-ca": init_ca()
    elif args.cmd == "register":
        if not args.user: print("[!] --user required."); return
        register(args.user, args.algo)
    elif args.cmd == "auth":
        if not args.user: print("[!] --user required."); return
        auth(args.user)
    elif args.cmd == "sign":
        if not args.user or not args.file: print("[!] --user and --file required."); return
        sign_doc(args.user, args.file)
    elif args.cmd == "verify":
        if not args.user or not args.file: print("[!] --user and --file required."); return
        verify_doc(args.user, args.file)
    elif args.cmd == "encrypt":
        if not args.user or not args.file or not args.target: print("[!] --user, --file, and --target required."); return
        encrypt_file(args.user, args.target, args.file)
    elif args.cmd == "decrypt":
        if not args.user or not args.file: print("[!] --user and --file required."); return
        decrypt_file(args.user, args.file)
    else: p.print_help()

if __name__ == "__main__":
    main()
