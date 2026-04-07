import argparse
import os
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ── Constantes ────────────────────────────────────────────────────────────────
MAX_FILE_SIZE = 1024          # 1 KB en bytes
KEY_SIZE      = 32            # AES-256: llave de 32 bytes
NONCE_SIZE    = 16            # Nonce de 16 bytes (recomendado por PyCryptodome)
TAG_SIZE      = 16            # Tag de autenticación GCM: 16 bytes
# El archivo .enc guarda: [nonce (16)] + [tag (16)] + [ciphertext (variable)]


# ── RF-02: Generación de llave ─────────────────────────────────────────────────
def generar_llave(ruta_salida: str) -> None:
    """
    Genera una llave aleatoria de 32 bytes (AES-256) y la guarda en disco.
    La llave es binaria pura, no se codifica en base64 para mantener simplicidad.
    """
    llave = get_random_bytes(KEY_SIZE)

    with open(ruta_salida, "wb") as f:
        f.write(llave)

    print(f"[OK] Llave generada ({KEY_SIZE} bytes / AES-256) → {ruta_salida}")


# ── RF-03: Cifrado ─────────────────────────────────────────────────────────────
def cifrar(ruta_texto: str, ruta_llave: str, ruta_salida: str) -> None:
    """
    Lee el archivo de texto plano, lo cifra con AES-256-GCM y guarda el resultado.

    Formato del archivo cifrado (.enc):
        [nonce: 16 bytes] + [tag: 16 bytes] + [ciphertext: N bytes]

    El nonce y el tag no son secretos pero son necesarios para descifrar y verificar.
    """
    # Validar tamaño máximo del archivo de entrada (RF-01)
    tamanio = os.path.getsize(ruta_texto)
    if tamanio > MAX_FILE_SIZE:
        print(f"[ERROR] El archivo supera 1 KB ({tamanio} bytes). Máximo permitido: {MAX_FILE_SIZE} bytes.")
        sys.exit(1)

    # Leer texto plano
    with open(ruta_texto, "rb") as f:
        plaintext = f.read()

    # Leer llave desde disco
    with open(ruta_llave, "rb") as f:
        llave = f.read()

    if len(llave) != KEY_SIZE:
        print(f"[ERROR] La llave debe tener {KEY_SIZE} bytes. Esta tiene {len(llave)}.")
        sys.exit(1)

    # Crear objeto cipher AES en modo GCM
    # GCM genera un nonce aleatorio automáticamente si no se provee uno
    cipher = AES.new(llave, AES.MODE_GCM)

    # Cifrar y obtener tag de autenticación en un solo paso
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Guardar: nonce + tag + ciphertext (todo junto en un archivo binario)
    with open(ruta_salida, "wb") as f:
        f.write(cipher.nonce)   # 16 bytes
        f.write(tag)            # 16 bytes
        f.write(ciphertext)     # N bytes (mismo tamaño que el plaintext)

    print(f"[OK] Archivo cifrado exitosamente → {ruta_salida}")
    print(f"     Tamaño original : {len(plaintext)} bytes")
    print(f"     Tamaño cifrado  : {os.path.getsize(ruta_salida)} bytes (incluye nonce + tag)")


# ── RF-04: Descifrado ──────────────────────────────────────────────────────────
def descifrar(ruta_cifrado: str, ruta_llave: str, ruta_salida: str) -> None:
    """
    Lee el archivo cifrado (.enc), verifica su integridad y lo descifra.

    Si el tag no coincide (archivo alterado o llave incorrecta), el proceso
    falla con un ValueError antes de devolver ningún dato.
    """
    # Leer llave desde disco
    with open(ruta_llave, "rb") as f:
        llave = f.read()

    if len(llave) != KEY_SIZE:
        print(f"[ERROR] La llave debe tener {KEY_SIZE} bytes. Esta tiene {len(llave)}.")
        sys.exit(1)

    # Leer archivo cifrado y separar sus partes
    with open(ruta_cifrado, "rb") as f:
        nonce      = f.read(NONCE_SIZE)   # Primeros 16 bytes: nonce
        tag        = f.read(TAG_SIZE)     # Siguientes 16 bytes: tag de autenticación
        ciphertext = f.read()             # El resto: datos cifrados

    # Crear objeto cipher con la misma llave y el mismo nonce usados al cifrar
    cipher = AES.new(llave, AES.MODE_GCM, nonce=nonce)

    # Descifrar y verificar autenticidad en un solo paso
    # Si el mensaje fue alterado o la llave es incorrecta, lanza ValueError
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        print("[ERROR] Verificación fallida. La llave es incorrecta o el archivo fue alterado.")
        sys.exit(1)

    # Guardar texto recuperado
    with open(ruta_salida, "wb") as f:
        f.write(plaintext)

    print(f"[OK] Archivo descifrado y verificado exitosamente → {ruta_salida}")
    print(f"     Contenido recuperado ({len(plaintext)} bytes):")
    print("─" * 50)
    print(plaintext.decode("utf-8"))
    print("─" * 50)


# ── RF-05: CLI ─────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Herramienta de cifrado AES-256-GCM para archivos de texto plano."
    )

    subparsers = parser.add_subparsers(dest="comando", required=True)

    # Subcomando: generar-llave
    p_gen = subparsers.add_parser("generar-llave", help="Genera una nueva llave AES-256.")
    p_gen.add_argument("--salida", default="llave.key", help="Archivo donde guardar la llave (default: llave.key)")

    # Subcomando: cifrar
    p_cifrar = subparsers.add_parser("cifrar", help="Cifra un archivo de texto plano.")
    p_cifrar.add_argument("--texto",  required=True, help="Archivo de texto plano a cifrar")
    p_cifrar.add_argument("--llave",  required=True, help="Archivo con la llave AES")
    p_cifrar.add_argument("--salida", required=True, help="Archivo de salida cifrado (.enc)")

    # Subcomando: descifrar
    p_descifrar = subparsers.add_parser("descifrar", help="Descifra un archivo cifrado.")
    p_descifrar.add_argument("--cifrado", required=True, help="Archivo cifrado (.enc)")
    p_descifrar.add_argument("--llave",   required=True, help="Archivo con la llave AES")
    p_descifrar.add_argument("--salida",  required=True, help="Archivo de salida con el texto recuperado")

    args = parser.parse_args()

    # Despachar al comando correspondiente
    if args.comando == "generar-llave":
        generar_llave(args.salida)

    elif args.comando == "cifrar":
        cifrar(args.texto, args.llave, args.salida)

    elif args.comando == "descifrar":
        descifrar(args.cifrado, args.llave, args.salida)


if __name__ == "__main__":
    main()