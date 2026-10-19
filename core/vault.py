import os
import shutil
from pathlib import Path
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Deriva una llave criptográfica segura a partir de la contraseña introducida
    y una sal aleatoria usando PBKDF2HMAC con SHA256 (390,000 iteraciones).
    Esto evita ataques de fuerza bruta rápidos.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

def seal_folder(folder_path: str, password: str) -> tuple[str, bytes]:
    """
    Comprime la carpeta objetivo en un archivo ZIP temporal, la cifra usando Fernet,
    elimina la carpeta original sin dejar rastro y guarda el cofre cifrado.
    Devuelve la ruta del cofre y la sal generada.
    """
    target = Path(folder_path)
    if not target.exists():
        raise FileNotFoundError("La ruta o carpeta objetivo no existe.")

    # 1. Comprimir la carpeta en un archivo ZIP temporal
    archive_path = shutil.make_archive(str(target), 'zip', target)
    
    # 2. Leer los bytes del archivo ZIP comprimido
    with open(archive_path, "rb") as f:
        data = f.read()
        
    # Borrar el ZIP temporal sin cifrar
    os.remove(archive_path)

    # 3. Generar una sal aleatoria de 16 bytes y derivar la llave de cifrado
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    # 4. Cifrar los datos y guardarlos en un archivo con extensión arcana (.rlyeh)
    encrypted_data = fernet.encrypt(data)
    vault_path = target.with_suffix(".rlyeh")
    
    with open(vault_path, "wb") as f:
        f.write(encrypted_data)

    # 5. Destruir los archivos originales de forma definitiva
    shutil.rmtree(target)

    return str(vault_path), salt

def unseal_folder(vault_path: str, salt: bytes, password: str) -> bool:
    """
    Intenta abrir el cofre descifrando los bytes con la contraseña y la sal.
    Si tiene éxito, descomprime el contenido restaurando la carpeta original.
    Devuelve True si se abrió con éxito, o False si la contraseña es incorrecta.
    """
    vault = Path(vault_path)
    if not vault.exists():
        raise FileNotFoundError("El archivo del cofre no se encuentra en la ruta esperada.")

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        # Leer el cofre cifrado
        with open(vault, "rb") as f:
            encrypted_data = f.read()
        
        # Intentar desencriptar
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Guardar temporalmente el ZIP desencriptado
        temp_zip = vault.with_suffix(".zip")
        with open(temp_zip, "wb") as f:
            f.write(decrypted_data)

        # Descomprimir en la ubicación original
        original_folder = vault.with_suffix("")
        shutil.unpack_archive(str(temp_zip), extract_dir=original_folder)
        
        # Limpieza de archivos temporales y borrado del cofre cifrado ya abierto
        os.remove(temp_zip)
        os.remove(vault)
        return True
        
    except Exception:
        # Si la contraseña falla o el archivo está alterado, saltará una excepción aquí
        return False