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
# CONFIGURACIÓN
# ======================================================

DATA_DIR = "X:/cloudA"          # nube principal (Drive montado)
VAULT_DIR = "X:/vault"         # copia confiable
MANIFEST_DIR = "./manifests"

CHUNK_SIZE = 4 * 1024 * 1024   # 4 MiB (óptimo)
THREADS = 8                   # paralelismo

PRIVATE_KEY = "./integrity/sign_key.pem"
PUBLIC_KEY  = "./integrity/sign_pub.pem"

USE_PKCS11 = False

# ======================================================


# =============================
# HASH BLAKE3
# =============================

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


# =============================
# MERKLE TREE (BLAKE3)
# =============================

def merkle_root(hashes):
    if not hashes:
        return blake3_hex(b"")

    nodes = hashes[:]

    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])

        new_level = []

        for i in range(0, len(nodes), 2):
            combined = (nodes[i] + nodes[i+1]).encode()
            new_level.append(blake3_hex(combined))

        nodes = new_level

    return nodes[0]


# =============================
# BUILD MANIFEST
# =============================

def hash_single_file(rel_path):
    full_path = os.path.join(DATA_DIR, rel_path)

    size = os.path.getsize(full_path)
    chunks = hash_file_chunks(full_path)
    root = merkle_root(chunks)

    return {
        "path": rel_path,
        "size": size,
        "chunks": chunks,
        "root": root
    }


def build_manifest():
    print("Generando hashes BLAKE3...")

    files = []

    rel_paths = []

    for root, _, filenames in os.walk(DATA_DIR):
        for f in filenames:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, DATA_DIR)
            rel_paths.append(rel)

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        files = list(ex.map(hash_single_file, rel_paths))

    manifest = {
        "timestamp": int(time.time()),
        "algorithm": "BLAKE3",
        "chunk_size": CHUNK_SIZE,
        "files": files
    }

    manifest["snapshot_root"] = merkle_root([f["root"] for f in files])

    return manifest


# =============================
# FIRMA (OpenSSL)
# =============================

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


# =============================
# VAULT COPY
# =============================

def sync_to_vault():
    print("Sincronizando Vault...")
    shutil.copytree(DATA_DIR, VAULT_DIR, dirs_exist_ok=True)


# =============================
# VERIFICACIÓN
# =============================

def rollback(rel_path):
    src = os.path.join(VAULT_DIR, rel_path)
    dst = os.path.join(DATA_DIR, rel_path)

    print(f"Restaurando {rel_path}")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)


def verify_file(file_info):
    rel = file_info["path"]
    full = os.path.join(DATA_DIR, rel)

    chunks = hash_file_chunks(full)
    root = merkle_root(chunks)

    if root != file_info["root"]:
        print(f"❌ Corrupción detectada: {rel}")
        rollback(rel)
        return False

    return True


def verify_manifest(manifest):
    print("Verificando integridad...")

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        results = list(ex.map(verify_file, manifest["files"]))

    return all(results)


# =============================
# SNAPSHOT
# =============================

def create_snapshot():
    Path(MANIFEST_DIR).mkdir(exist_ok=True)

    manifest = build_manifest()

    name = f"manifest_{manifest['timestamp']}.json"
    path = os.path.join(MANIFEST_DIR, name)

    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)

    sign_manifest(path)
    sync_to_vault()

    print("✅ Snapshot creado:", path)


# =============================
# VERIFY
# =============================

def verify_latest():
    files = sorted(Path(MANIFEST_DIR).glob("manifest_*.json"))
    latest = str(files[-1])

    verify_signature(latest)

    with open(latest) as f:
        manifest = json.load(f)

    ok = verify_manifest(manifest)

    if ok:
        print("✅ Integridad OK")
    else:
        print("⚠ Rollback ejecutado")


# =============================
# CLI
# =============================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: snapshot | verify")
        exit()

    cmd = sys.argv[1]

    if cmd == "snapshot":
        create_snapshot()

    elif cmd == "verify":
        # Bucle infinito cada 1 min
        print("Verificación automática cada minuto. Presiona Ctrl+C para parar.")
        try:
            while True:
                print("\n⏱ Comenzando verificación...")
                verify_latest()
                print("✅ Esperando 1 minuto para la siguiente verificación...\n")
                time.sleep(60)
        except KeyboardInterrupt:
            print("\n🛑 Verificación interrumpida por el usuario")
