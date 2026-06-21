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
