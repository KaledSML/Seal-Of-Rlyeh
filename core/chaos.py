import os
import random
import shutil
from pathlib import Path

def relocate_vault(current_vault_path: str) -> str:
    """
    Mecánica de Caos: Si se agotan los intentos de desbloqueo, el cofre se muda 
    de forma aleatoria a una subcarpeta dentro del directorio 'Documentos' de Windows 
    para ocultarse de cualquier intruso.
    """
    vault = Path(current_vault_path)
    if not vault.exists():
        return current_vault_path

    # Obtener la ruta de la carpeta Documentos del usuario en Windows
    docs_path = Path.home() / "Documents"
    if not docs_path.exists():
        docs_path = Path.home()  # Fallback por seguridad si la ruta no existe

    # Buscar todas las subcarpetas disponibles en Documentos para elegir una al azar
    subfolders = [x for x in docs_path.iterdir() if x.is_dir()]
    
    # Si hay carpetas, elegimos una de forma aleatoria; si no, lo dejamos en la raíz de Documentos
    if subfolders:
        destination_dir = random.choice(subfolders)
    else:
        destination_dir = docs_path

    # Definir la nueva ruta para el cofre cifrado
    new_vault_path = destination_dir / vault.name
    
    # Si por casualidad ya existiera un archivo con el mismo nombre allí, lo purgamos
    if new_vault_path.exists():
        new_vault_path.unlink()

    # Mover el archivo físico a su nueva guarida secreta
    shutil.move(str(vault), str(new_vault_path))
    
    # Devolvemos la nueva ruta para actualizarla en el archivo de configuración
    return str(new_vault_path)