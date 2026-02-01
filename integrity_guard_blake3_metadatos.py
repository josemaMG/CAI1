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

DATA_DIR = "X:/cloudA"          # nube principal (Drive montado)
VAULT_DIR = "X:/vault"           # copia confiable
MANIFEST_DIR = "./manifests"

CHUNK_SIZE = 4 * 1024 * 1024    # 4 MiB (óptimo encontrado)
THREADS = 8                      # paralelismo

PRIVATE_KEY = "./integrity/sign_key.pem"
PUBLIC_KEY  = "./integrity/sign_pub.pem"

USE_PKCS11 = False

# ======================================================

# =============================
# Hash mediante blake3
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
# Creación del Árbol Merkle mediante BLAKE3
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
# Creación del Manifest incluyendo metadatos
# =============================

def hash_file_with_metadata(rel_path):
    """
    Genera hashes BLAKE3 de un archivo incluyendo:
      - contenido
      - tamaño
      - timestamps (modificación, creación)
      - nombre relativo
    """
    full_path = os.path.join(DATA_DIR, rel_path)

    # Hash de chunks del contenido
    chunks = hash_file_chunks(full_path)

    # Obtener metadatos
    stat = os.stat(full_path)
    metadata_bytes = (
        rel_path.encode("utf-8") +                   # ruta relativa
        str(stat.st_size).encode("utf-8") +          # tamaño
        str(int(stat.st_mtime)).encode("utf-8") +    # fecha modificación
        str(int(stat.st_birthtime)).encode("utf-8")  # fecha creación
    )

    # Mezclar el hash de cada chunk con los metadatos
    combined_hashes = [blake3_hex(c.encode() + metadata_bytes) for c in chunks]

    # Raíz Merkle con los hashes combinados
    root = merkle_root(combined_hashes)

    return {
        "path": rel_path,
        "size": stat.st_size,
        "chunks": combined_hashes,
        "root": root,
        "metadata": {
            "mtime": stat.st_mtime,
            "birthtime": stat.st_birthtime
        }
    }

def build_manifest():
    print("Generando hashes BLAKE3 con metadatos...")

    files = []

    rel_paths = []

    for root, _, filenames in os.walk(DATA_DIR):
        for f in filenames:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, DATA_DIR)
            rel_paths.append(rel)

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        files = list(ex.map(hash_file_with_metadata, rel_paths))

    manifest = {
        "timestamp": int(time.time()),
        "algorithm": "BLAKE3",
        "chunk_size": CHUNK_SIZE,
        "files": files
    }

    manifest["snapshot_root"] = merkle_root([f["root"] for f in files])

    return manifest

# =============================
# Firma mediante OpenSSL
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
# Copia hacia Vault
# =============================

def sync_to_vault():
    print("Sincronizando Vault...")
    shutil.copytree(DATA_DIR, VAULT_DIR, dirs_exist_ok=True)

# =============================
# Verificación y Rollback
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
    # Incluir metadatos al hash de verificación
    stat = os.stat(full)
    metadata_bytes = (
        rel.encode("utf-8") +
        str(stat.st_size).encode("utf-8") +
        str(int(stat.st_mtime)).encode("utf-8") +
        str(int(stat.st_birthtime)).encode("utf-8")
    )
    combined_hashes = [blake3_hex(c.encode() + metadata_bytes) for c in chunks]
    root = merkle_root(combined_hashes)

    if root != file_info["root"]:
        print(f"Corrupción detectada: {rel}")
        rollback(rel)
        return False

    return True


def verify_manifest(manifest):
    print("Verificando integridad...")

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        results = list(ex.map(verify_file, manifest["files"]))

    return all(results)

# =============================
# Snapshot
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

    print("Snapshot creado:", path)

# =============================
# Verificación
# =============================

def verify_latest():
    files = sorted(Path(MANIFEST_DIR).glob("manifest_*.json"))
    latest = str(files[-1])

    verify_signature(latest)

    with open(latest) as f:
        manifest = json.load(f)

    ok = verify_manifest(manifest)

    if ok:
        print("Integridad OK")
    else:
        print("Rollback ejecutado")

# =============================
# Terminal
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
        print("Verificacion automatica cada minuto. Presiona Ctrl+C para parar.")
        try:
            while True:
                print("\nComenzando verificacion...")
                verify_latest()
                print("Esperando 1 minuto para la siguiente verificacion...\n")
                time.sleep(60)
        except KeyboardInterrupt:
            print("\nVerificacion interrumpida por el usuario")
