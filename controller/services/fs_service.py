import os
import shutil


def copy_tree(src: str, dst: str) -> None:
    """Recursively copy a directory tree with metadata preservation.

    - Creates destination directories as needed.
    - Preserves file metadata via shutil.copy2.
    """
    os.makedirs(dst, exist_ok=True)
    for root, _dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        target_root = os.path.join(dst, rel) if rel != "." else dst
        os.makedirs(target_root, exist_ok=True)
        for f in files:
            shutil.copy2(os.path.join(root, f), os.path.join(target_root, f))
