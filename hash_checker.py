import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Union


class HashDatabase:
    def __init__(
        self, database_path: Union[str, Path] = "database/known_hashes.json"
    ) -> None:
        self.database_path = Path(database_path)
        self.known_hashes = self.load_database()

    def load_database(self) -> Dict[str, Any]:
        if not self.database_path.exists():
            return {}

        with self.database_path.open("r", encoding="utf-8") as file:
            content = file.read().strip()

        if not content:
            return {}

        data = json.loads(content)

        if not isinstance(data, dict):
            raise ValueError("Hash database must be a JSON object.")

        return {str(key).lower(): value for key, value in data.items()}

    def save_database(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self.database_path.open("w", encoding="utf-8") as file:
            json.dump(self.known_hashes, file, indent=4, ensure_ascii=False)

    def add_entry(self, sha256: str, metadata: Any = None) -> None:
        key = sha256.strip().lower()
        if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("Invalid SHA-256 hash.")
        self.known_hashes[key] = metadata if metadata is not None else {}
        self.save_database()

    def calculate_hash(self, file_path: Union[str, Path]) -> Dict[str, str]:
        algorithms = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256(),
        }

        with Path(file_path).open("rb") as file:
            while chunk := file.read(8192):
                for algorithm in algorithms.values():
                    algorithm.update(chunk)

        return {
            name: algorithm.hexdigest()
            for name, algorithm in algorithms.items()
        }

    def analyse_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not path.is_file():
            raise IsADirectoryError(f"Not a file: {file_path}")

        hashes = self.calculate_hash(path)
        sha256 = hashes["sha256"]
        matched = sha256 in self.known_hashes

        return {
            "file_name": path.name,
            "file_path": str(path.resolve()),
            "file_size": path.stat().st_size,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hashes": hashes,
            "status": "known" if matched else "unknown",
            "match": self.known_hashes.get(sha256),
        }

    def scan_directory(self, directory: Union[str, Path]) -> List[Dict[str, Any]]:
        directory_path = Path(directory)
        if not directory_path.exists() or not directory_path.is_dir():
            raise NotADirectoryError(f"Directory not found: {directory_path}")

        results = []
        for file_path in directory_path.rglob("*"):
            if not file_path.is_file():
                continue

            try:
                results.append(self.analyse_file(file_path))
            except OSError as error:
                results.append(
                    {
                        "file_path": str(file_path),
                        "status": "ERROR",
                        "error": str(error),
                    }
                )

        return results

    def export_results(
        self,
        results: List[Dict[str, Any]],
        output_file: Union[str, Path],
    ) -> Path:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(results, file, indent=4, ensure_ascii=False)

        return output_path
