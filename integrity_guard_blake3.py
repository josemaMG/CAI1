import os
import json
import time
import shutil
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import blake3

# ======================================================
# Configuración
# ======================================================

DATA_DIR = "C:/cloudA" # Directorio local de los 15 gb sincronizados

VAULT_DIR = "C:/vault" # Directorio local de la copia de los 15 gb

MANIFEST_DIR = "./manifests"

REMOTE = "gdrive:cloudA" # Remoto rclone (Drive) NO CAMBIAR

CHUNK_SIZE = 4 * 1024 * 1024
THREADS = 8

PRIVATE_KEY = "./integrity/sign_key.pem"
PUBLIC_KEY  = "./integrity/sign_pub.pem"

# ======================================================
# rclone optimizado
# ======================================================

RCLONE_BASE_FLAGS = [
    "--fast-list",
    "--transfers", "3",
    "--checkers", "32",
    "--drive-chunk-size", "256M",
    "--multi-thread-streams", "12",
    "--buffer-size", "256M",
    "--use-mmap",
    "--progress"
]


# ======================================================
# Hash BLAKE3
# ======================================================

def blake3_hex(data: bytes) -> str:
    return blake3.blake3(data).hexdigest()


def hash_file_chunks(path):
    hashes = []
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hashes.append(blake3_hex(chunk))
    return hashes

# ======================================================
# Árbol Merkle
# ======================================================

def merkle_root(hashes):
    if not hashes:
        return blake3_hex(b"")

    nodes = hashes[:]

    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])

        new = []
        for i in range(0, len(nodes), 2):
            new.append(blake3_hex((nodes[i] + nodes[i+1]).encode()))
        nodes = new

    return nodes[0]

# ======================================================
# Manifest
# ======================================================

def hash_file_with_metadata(rel_path):
    full_path = os.path.join(DATA_DIR, rel_path)

    chunks = hash_file_chunks(full_path)
    stat = os.stat(full_path)

    metadata = (
        rel_path.encode() +
        str(stat.st_size).encode() +
        str(int(stat.st_mtime)).encode()
    )

    combined = [blake3_hex(c.encode() + metadata) for c in chunks]
    root = merkle_root(combined)

    return {
        "path": rel_path,
        "root": root
    }


def build_manifest():
    rel_paths = []

    for root, _, files in os.walk(DATA_DIR):
        for f in files:
            full = os.path.join(root, f)
            rel_paths.append(os.path.relpath(full, DATA_DIR))

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        files = list(ex.map(hash_file_with_metadata, rel_paths))

    return {
        "timestamp": int(time.time()),
        "files": files
    }

# ======================================================
# OpenSSL
# ======================================================

def sign_manifest(path):
    subprocess.run([
        "openssl", "dgst", "-sha256",
        "-sign", PRIVATE_KEY,
        "-out", path + ".sig",
        path
    ], check=True)


def verify_signature(path):
    subprocess.run([
        "openssl", "dgst", "-sha256",
        "-verify", PUBLIC_KEY,
        "-signature", path + ".sig",
        path
    ], check=True)

# ======================================================
# Vault
# ======================================================

def sync_to_vault():
    print("Actualizando Vault local...")
    shutil.copytree(DATA_DIR, VAULT_DIR, dirs_exist_ok=True)

# ======================================================
# Rollback
# ======================================================

def rollback(rel):
    src = os.path.join(VAULT_DIR, rel)
    dst = os.path.join(DATA_DIR, rel)

    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    print(f"Restaurado {rel}")

# ======================================================
# Verificación de archivos
# ======================================================

def verify_file(info):
    rel = info["path"]
    full = os.path.join(DATA_DIR, rel)

    if not os.path.exists(full):
        rollback(rel)
        return False

    chunks = hash_file_chunks(full)
    root = merkle_root(chunks)

    if root != info["root"]:
        rollback(rel)
        return False

    return True


def verify_manifest(manifest):
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        results = list(ex.map(verify_file, manifest["files"]))

    return all(results)

# ======================================================
# rclone Download/upload
# ======================================================

def rclone_copy(src, dst):
    cmd = ["rclone", "copy", src, dst] + RCLONE_BASE_FLAGS

    subprocess.run(cmd, check=True)


def download_from_drive():
    print("Descargando desde Drive...")
    rclone_copy(REMOTE, DATA_DIR)


def upload_to_drive():
    print("Subiendo a Drive...")
    rclone_copy(DATA_DIR, REMOTE)

# ======================================================
# Snapshot
# ======================================================

def create_snapshot():
    Path(MANIFEST_DIR).mkdir(exist_ok=True)

    manifest = build_manifest()

    name = f"manifest_{manifest['timestamp']}.json"
    path = os.path.join(MANIFEST_DIR, name)

    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)

    sign_manifest(path)
    sync_to_vault()

    print("Snapshot creado")

# ======================================================
# Ciclo completo
# ======================================================

def full_cycle():
    download_from_drive()

    files = sorted(Path(MANIFEST_DIR).glob("manifest_*.json"))
    if not files:
        print("No hay manifest, creando snapshot inicial")
        create_snapshot()
        upload_to_drive()
        return

    latest = str(files[-1])

    verify_signature(latest)

    with open(latest) as f:
        manifest = json.load(f)

    ok = verify_manifest(manifest)

    if ok:
        print("Integridad OK ✓")
        upload_to_drive()
    else:
        print("Se corrigieron archivos -> subiendo versión sana")
        upload_to_drive()

# ======================================================
# Main
# ======================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: snapshot | verify")
        exit()

    cmd = sys.argv[1]

    if cmd == "snapshot":
        create_snapshot()

    elif cmd == "verify":
        print("Verificando cada 60s (Drive -> Local -> Vault)")
        try:
            while True:
                full_cycle()
                time.sleep(60)
        except KeyboardInterrupt:
            print("Finalizado")
