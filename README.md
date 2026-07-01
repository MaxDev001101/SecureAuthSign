# SecureAuthSign

A command-line cryptographic tool leveraging Public Key Infrastructure (PKI) to provide authentication, data integrity, and confidentiality for secure document exchange.

##  Features
- **Authentication:** Challenge-response proof of private key possession.
- **Integrity:** SHA-256 + RSA-PSS digital signatures detect any document tampering.
- **Confidentiality:** Hybrid encryption (AES-256-GCM + RSA-OAEP) ensures only the intended recipient can read files.
- **Key Management:** Local Certificate Authority (CA) issues and validates X.509 certificates.
- **Revocation:** JSON-based Certificate Revocation List (CRL) to block compromised keys.
- **Attack Mitigation:** Proven defenses against MITM, replay, and forgery attacks.

##  Installation
1. Clone or download this repository.
2. Ensure Python 3.10+ is installed.
3. Install dependencies:
   ```bash
   pip install -r requirements.txt

## 🚀 Quick Start Guide

Follow these exact steps to use the tool. Replace `alice`, `bob`, and `document.txt` with your own names and files.

### 1. Setup the Trust System
Create the central authority that issues digital IDs:
```bash
python main.py init-ca
```

### 2. Register Users
Create digital identities (key pairs + certificates) for the sender and receiver:
```bash
python main.py register --user alice
python main.py register --user bob
```

### 3. Prove Identity (Authentication)
Alice proves she owns her private key without revealing it:
```bash
python main.py auth --user alice
```

### 4. Sign a File (Integrity)
Alice creates a digital signature that locks the file to her identity:
```bash
python main.py sign --user alice --file document.txt
```

### 5. Verify the File
Anyone can check if the file is truly from Alice and hasn't been changed:
```bash
python main.py verify --user alice --file document.txt
```

### 6. Encrypt the File (Confidentiality)
Alice locks the file so only Bob can open it:
```bash
python main.py encrypt --user alice --file document.txt --target bob
```

### 7. Decrypt the File
Bob unlocks and reads the original file using his private key:
```bash
python main.py decrypt --user bob --file document.txt.enc
```
### Run Tests
Validate security controls against simulated attacks:
```bash
python -m pytest tests/test_attacks.py -v
```
