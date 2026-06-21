import json, os

class RevocationRegistry:
    """Custom structure for certificate revocation tracking"""
    def __init__(self, filepath="data/crl.json"):
        self.filepath = filepath
        os.makedirs("data", exist_ok=True)
        self.revoked_serials = set(self._load())

    def _load(self):
        if os.path.exists(self.filepath):
            with open(self.filepath, "r") as f:
                return json.load(f)
        return []

    def revoke(self, serial_number: int, reason: str = "Unspecified"):
        self.revoked_serials.add(serial_number)
        self._save()

    def is_revoked(self, serial_number: int) -> bool:
        return serial_number in self.revoked_serials

    def _save(self):
        with open(self.filepath, "w") as f:
            json.dump(list(self.revoked_serials), f)
