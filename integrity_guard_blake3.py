#!/usr/bin/env python3
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

DATA_DIR = os.path.abspath("C:/cloudA")
VAULT_DIR = os.path.abspath("C:/vault")
MANIFEST_DIR = os.path.abspath("./manifests")
REMOTE = "gdrive:cloudA"

CHUNK_SIZE = 4 * 1024 * 1024
THREADS = 8

PRIVATE_KEY = os.path.abspath("./integrity/sign_key.pem")
PUBLIC_KEY  = os.path.abspath("./integrity/sign_pub.pem")

# ======================================================
# rclone flags
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
# BLAKE3 hash
# ======================================================

def blake3_hex(data: bytes) -> str:
    return blake3.blake3(data).hexdigest()

def hash_file_chunks(path):
    hashes = []
    if not os.path.exists(path): return []
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
# Manifest (Fuente de Verdad: VAULT)
# ======================================================

def hash_file_with_metadata(rel_path, base_dir):
    full_path = os.path.join(base_dir, rel_path)
    chunks = hash_file_chunks(full_path)
    stat = os.stat(full_path)
    metadata = (
        rel_path.encode() +
        str(stat.st_size).encode() +
        str(int(stat.st_mtime)).encode()
    )
    combined = [blake3_hex(c.encode() + metadata) for c in chunks]
    root = merkle_root(combined)
    return {"path": rel_path, "root": root}

def build_manifest():
    rel_paths = []
    for root, _, files in os.walk(VAULT_DIR):
        for f in files:
            full = os.path.join(root, f)
            rel_paths.append(os.path.relpath(full, VAULT_DIR))
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        files = list(ex.map(lambda p: hash_file_with_metadata(p, VAULT_DIR), rel_paths))
    return {"timestamp": int(time.time()), "files": files}

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
# Rollback
# ======================================================

def rollback(rel):
    src = os.path.join(VAULT_DIR, rel)
    dst = os.path.join(DATA_DIR, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    print(f"Restaurado {rel}")

# ======================================================
# Verificación
# ======================================================

def verify_file(info):
    rel = info["path"]
    full = os.path.join(DATA_DIR, rel)

    if not os.path.exists(full):
        print(f"Archivo faltante en local: {rel}")
        rollback(rel)
        return False

    current_data = hash_file_with_metadata(rel, DATA_DIR)

    if current_data["root"] != info["root"]:
        print(f"Archivo corrupto detectado: {rel}")
        rollback(rel)
        return False

    return True


def verify_manifest(manifest):
    """
    Verifica todos los archivos del manifiesto.
    Retorna True si todos OK, False si alguno faltante o corrupto.
    También devuelve la lista de archivos problemáticos.
    """
    problem_files = []

    def check_and_record(info):
        if not verify_file(info):
            problem_files.append(info["path"])

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        list(ex.map(check_and_record, manifest["files"]))

    if problem_files:
        print("Archivos problemáticos:", problem_files)
        return False, problem_files

    return True, []




# ======================================================
# rclone
# ======================================================

def download_from_drive():
    print("Descargando desde Drive...")
    cmd = ["rclone", "copy", REMOTE, DATA_DIR] + RCLONE_BASE_FLAGS
    subprocess.run(cmd, check=True)


def upload_to_drive():
    print("Subiendo a Drive...")
    cmd = [
        "rclone", "copy", DATA_DIR, REMOTE,
        "--update",
        "--checksum",
    ] + RCLONE_BASE_FLAGS
    subprocess.run(cmd, check=True)


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
    print("Snapshot creado")
    return manifest

# ==============================
# Ciclo completo
# ==============================

def full_cycle():
    download_from_drive()

    # Buscar el manifiesto más reciente
    files = sorted(Path(MANIFEST_DIR).glob("manifest_*.json"))
    if not files:
        print("No hay manifest, creando snapshot inicial")
        manifest = create_snapshot()
        upload_to_drive()
        return

    latest = str(files[-1])
    verify_signature(latest)
    with open(latest) as f:
        manifest = json.load(f)

    ok, problem_files = verify_manifest(manifest)

    if ok:
        print("Integridad OK")
    else:
        print("Archivos corruptos o faltantes detectados, restaurando desde Vault...")
        for f in problem_files:
            print(f"Restaurado: {f}")
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
        upload_to_drive()

    elif cmd == "verify":
        print("Verificando cada 60s (Drive -> Local -> Vault)")
        try:
            while True:
                full_cycle()
                print("Esperando 60 segundos...")
                time.sleep(60)
        except KeyboardInterrupt:
            print("Finalizado")