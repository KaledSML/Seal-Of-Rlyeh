
from pathlib import Path
import os
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"RLYEH01!"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
HEADER_SIZE = len(MAGIC) + SALT_SIZE + NONCE_SIZE


def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("La contraseña no puede estar vacía.")

    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=2**15,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))


def _write_new_file(destination: Path, data: bytes) -> None:
    """Escribe en un temporal y publica el archivo sin sobrescribir."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=".rlyeh-",
            suffix=".tmp",
            delete=False,
        ) as output:
            temp_path = Path(output.name)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())

        # En Windows, os.link falla si el destino ya existe.
        # El temporal y el destino están en el mismo volumen.
        os.link(temp_path, destination)

    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def encrypt_file(source: str, destination: str, password: str) -> None:
    src = Path(source)
    dst = Path(destination)

    if not src.is_file():
        raise FileNotFoundError(f"No existe el archivo: {src}")
    if src.resolve() == dst.resolve():
        raise ValueError("El origen y el destino deben ser diferentes.")
    if dst.exists():
        raise FileExistsError(f"El destino ya existe: {dst}")

    plaintext = src.read_bytes()
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = MAGIC + salt + nonce

    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)

    _write_new_file(dst, header + ciphertext)


def decrypt_file(source: str, destination: str, password: str) -> None:
    src = Path(source)
    dst = Path(destination)

    if not src.is_file():
        raise FileNotFoundError(f"No existe el contenedor: {src}")
    if src.resolve() == dst.resolve():
        raise ValueError("El origen y el destino deben ser diferentes.")
    if dst.exists():
        raise FileExistsError(f"El destino ya existe: {dst}")

    data = src.read_bytes()

    if len(data) < HEADER_SIZE + 16:
        raise ValueError("Contenedor incompleto o inválido.")
    if data[:len(MAGIC)] != MAGIC:
        raise ValueError("El archivo no es un contenedor RLYEH compatible.")

    salt_start = len(MAGIC)
    nonce_start = salt_start + SALT_SIZE
    nonce_end = nonce_start + NONCE_SIZE

    salt = data[salt_start:nonce_start]
    nonce = data[nonce_start:nonce_end]
    header = data[:HEADER_SIZE]
    ciphertext = data[HEADER_SIZE:]

    key = derive_key(password, salt)

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise ValueError(
            "Contraseña incorrecta o contenedor alterado."
        ) from None

    _write_new_file(dst, plaintext)
