import os
import json
from collections import defaultdict

class SignatureDatabase:
    def __init__(self, db_path='signature_db.json'):
        self.db_path = db_path
        self.signatures = self._load_database()

    def _load_database(self):
        if not os.path.exists(self.db_path):
            return defaultdict(list)
        try:
            with open(self.db_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return defaultdict(list)

    def _save_database(self):
        with open(self.db_path, 'w') as f:
            json.dump(self.signatures, f, indent=2)

    def add_signature(self, file_type, signature):
        if file_type not in self.signatures:
            self.signatures[file_type] = []
        self.signatures[file_type].append(signature)
        self._save_database()

    def remove_signature(self, file_type, signature):
        if file_type in self.signatures and signature in self.signatures[file_type]:
            self.signatures[file_type].remove(signature)
            self._save_database()

    def list_signatures(self):
        return self.signatures

    def clear_database(self):
        self.signatures = defaultdict(list)
        self._save_database()


def main():
    db = SignatureDatabase()
    print("Current Signatures:", db.list_signatures())

    # Example: Add some signatures
    db.add_signature("JPEG", "FFD8FF")
    db.add_signature("PNG", "89504E47")
    db.add_signature("ZIP", "504B0304")
    print("After Adding Signatures:", db.list_signatures())

    # Example: Remove a signature
    db.remove_signature("JPEG", "FFD8FF")
    print("After Removing JPEG Signature:", db.list_signatures())

    # Example: Clear database
    db.clear_database()
    print("After Clearing Database:", db.list_signatures())


if __name__ == "__main__":
    main()