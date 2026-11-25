"""Run: python -m examples.serialization_demo [new-output-file.json]"""
import sys
from pathlib import Path
from ibe_project.hybrid import IBEWorkflow
from ibe_project.serialization import save, load


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("artifacts/message.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    workflow = IBEWorkflow()
    public, master = workflow.setup()
    message = b"Saved before Alice enrolled. Binary bytes: \x00\xff"
    envelope = workflow.encrypt(public, "alice@example.com", message)
    size = save(workflow.group, envelope, path)
    loaded = load(workflow.group, path)
    key = workflow.issue_key(master, "alice@example.com")
    if workflow.decrypt(public, key, loaded) != message:
        raise RuntimeError("File round trip failed")
    print(f"PASS: saved, loaded and decrypted {path} ({size} JSON bytes)")
    print("Public parameters and private keys remain in memory for this demo.")
    print("The encrypted file alone cannot recreate them after exit.")


if __name__ == "__main__":
    main()
