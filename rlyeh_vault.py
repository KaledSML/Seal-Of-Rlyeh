
# ============================================================
# IMPORTACIONES
# Herramientas necesarias para manejar rutas, archivos,
# carpetas, archivos ZIP y operaciones temporales.
# ============================================================

from pathlib import Path, PurePosixPath
import os
import stat
import tempfile
import zipfile

from rlyeh_crypto import encrypt_file, decrypt_file


# ============================================================
# LÍMITES DE SEGURIDAD
# Evitan procesar contenedores con demasiadas entradas
# o archivos que superen los tamaños permitidos.
# ============================================================

MAX_MEMBERS = 10_000
MAX_FILE_SIZE = 512 * 1024 * 1024
MAX_TOTAL_SIZE = 2 * 1024 * 1024 * 1024


# ============================================================
# SELLAR ARCHIVOS Y CARPETAS
# 1. Validar el origen y destino.
# 2. Crear un ZIP temporal.
# 3. Cifrar el ZIP.
# 4. Publicar el contenedor .rlyeh.
# ============================================================

def seal_path(source, destination, password):
    original = Path(source)

    # Rechazar orígenes inexistentes o enlaces simbólicos.
    if original.is_symlink() or not original.exists():
        raise ValueError("El origen no existe o es un enlace simbólico.")

    src = original.resolve()
    dst = Path(destination).resolve()

    # Validar el tipo de origen y evitar sobrescrituras.
    if not (src.is_file() or src.is_dir()):
        raise ValueError("El origen debe ser un archivo o una carpeta.")
    if dst.exists():
        raise FileExistsError(f"El destino ya existe: {dst}")

    # Evitar guardar el contenedor dentro de la carpeta original.
    if src == dst or (src.is_dir() and src in dst.parents):
        raise ValueError("El contenedor no puede estar dentro del origen.")

    dst.parent.mkdir(parents=True, exist_ok=True)

    # Crear un espacio de trabajo temporal junto al destino.
    with tempfile.TemporaryDirectory(dir=dst.parent) as work:
        work = Path(work)
        archive = work / "payload.zip"
        encrypted = work / "payload.rlyeh"

        # Crear el ZIP con el archivo o contenido de la carpeta.
        with zipfile.ZipFile(
            archive, "w", compression=zipfile.ZIP_DEFLATED
        ) as zf:
            paths = [src]

            if src.is_dir():
                paths.extend(sorted(src.rglob("*")))

            for item in paths:

                # No permitir enlaces simbólicos dentro del origen.
                if item.is_symlink():
                    raise ValueError(
                        f"No se admiten enlaces simbólicos: {item}"
                    )

                # Conservar el nombre del origen y su estructura interna.
                relative = (
                    Path(src.name)
                    if item == src
                    else Path(src.name) / item.relative_to(src)
                )
                name = relative.as_posix()

                # Guardar directorios y archivos en el ZIP.
                if item.is_dir():
                    zf.writestr(name.rstrip("/") + "/", b"")
                elif item.is_file():
                    zf.write(item, name)

        # Cifrar el ZIP y generar el contenedor temporal.
        encrypt_file(str(archive), str(encrypted), password)

        # Publicar el contenedor final.
        # No sobrescribe un destino que ya exista.
        os.rename(encrypted, dst)


# ============================================================
# VALIDACIÓN DE ENTRADAS ZIP
# Revisa todos los nombres, tipos y tamaños ANTES de extraer.
# Esta función no extrae archivos: solamente inspecciona.
# ============================================================

def _safe_members(zf):
    members = []
    seen = {}
    total_size = 0
    infos = zf.infolist()

    # Limitar la cantidad de entradas del ZIP.
    if len(infos) > MAX_MEMBERS:
        raise ValueError("El contenedor contiene demasiados archivos.")

    # Revisar cada entrada individualmente.
    for info in infos:
        name = info.filename

        # Rechazar rutas vacías, separadores Windows,
        # rutas absolutas y caracteres nulos.
        if (
            not name
            or "\\" in name
            or name.startswith("/")
            or "\x00" in name
        ):
            raise ValueError("Ruta insegura dentro del contenedor.")

        path = PurePosixPath(name)

        # Rechazar rutas absolutas o sin componentes.
        if path.is_absolute() or not path.parts:
            raise ValueError("El contenedor contiene una ruta peligrosa.")

        parts = name.rstrip("/").split("/")

        # Rechazar componentes vacíos, "." y "..".
        if any(part in ("", ".", "..") for part in parts):
            raise ValueError("El contenedor contiene una ruta peligrosa.")

        # Evitar unidades, rutas especiales y flujos alternativos
        # de Windows, por ejemplo C: o archivo.txt:secreto.
        if any(":" in part for part in parts):
            raise ValueError("Ruta o unidad no permitida.")

        # Rechazar nombres de dispositivos reservados en Windows.
        reserved = {
            "CON", "PRN", "AUX", "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }

        for part in parts:
            if part.endswith((" ", ".")):
                raise ValueError("Nombre de archivo inválido en Windows.")
            stem = part.split(".")[0].upper()

            if stem in reserved:
                raise ValueError("Nombre de archivo reservado en Windows.")

        # Rechazar entradas ZIP cifradas.
        # El cifrado del proyecto ya protege el contenedor completo.
        if info.flag_bits & 1:
            raise ValueError("No se admiten entradas ZIP cifradas.")

        # Comprobar el tamaño de cada archivo.
        if info.file_size < 0 or info.file_size > MAX_FILE_SIZE:
            raise ValueError("Un archivo supera el límite permitido.")

        # Comprobar el tamaño total acumulado.
        total_size += info.file_size

        if total_size > MAX_TOTAL_SIZE:
            raise ValueError("El contenido supera el límite de extracción.")

        # Identificar el tipo de entrada según sus atributos ZIP.
        mode = (info.external_attr >> 16) & 0xFFFF
        kind = stat.S_IFMT(mode)

        # Solo permitir archivos normales, directorios
        # o entradas sin tipo Unix definido.
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise ValueError("Tipo de archivo no permitido.")

        is_dir = info.is_dir() or kind == stat.S_IFDIR

        # Normalizar la ruta para comparar entradas.
        normalized = path.as_posix().rstrip("/")

        # Comparar ignorando mayúsculas y minúsculas.
        # Evita colisiones como Nota.txt y nota.txt en Windows.
        normalized_key = normalized.casefold()

        # Rechazar rutas duplicadas.
        if normalized_key in seen:
            raise ValueError("El contenedor contiene rutas duplicadas.")

        seen[normalized_key] = is_dir

        # Guardar la información validada para la extracción posterior.
        members.append((info, path, kind, is_dir))

    # Comprobar que ningún archivo sea padre de otra entrada.
    # Ejemplo inválido: archivo.txt y archivo.txt/secreto.txt.
    for _, path, _, _ in members:
        parts = path.parts

        for i in range(1, len(parts)):
            parent = PurePosixPath(*parts[:i]).as_posix()

            if seen.get(parent.casefold()) is False:
                raise ValueError(
                    "Un archivo del contenedor contiene otras rutas."
                )

    return members


# ============================================================
# ABRIR CONTENEDORES
# 1. Validar el contenedor y el destino.
# 2. Descifrar el ZIP.
# 3. Validar sus entradas.
# 4. Extraer en una carpeta temporal.
# 5. Publicar la recuperación completa.
# ============================================================

def open_container(container, output_dir, password):
    original = Path(container)

    # Verificar que el contenedor exista y no sea un enlace simbólico.
    if original.is_symlink() or not original.is_file():
        raise FileNotFoundError("No existe un contenedor válido.")

    src = original.resolve()
    dst = Path(output_dir).resolve()

    # Evitar sobrescribir una carpeta de salida existente.
    if dst.exists():
        raise FileExistsError(
            f"La carpeta de salida ya existe: {dst}"
        )

    dst.parent.mkdir(parents=True, exist_ok=True)

    # Preparar un espacio de trabajo temporal.
    with tempfile.TemporaryDirectory(dir=dst.parent) as work:
        work = Path(work)
        archive = work / "payload.zip"
        staging = work / "extracted"
        staging.mkdir()

        # Descifrar el contenedor y recuperar el ZIP.
        decrypt_file(str(src), str(archive), password)

        # Inspeccionar y extraer el contenido del ZIP.
        with zipfile.ZipFile(archive, "r") as zf:

            # Validar todas las entradas antes de extraer.
            members = _safe_members(zf)

            # Comprobar la integridad CRC de las entradas ZIP.
            if zf.testzip() is not None:
                raise ValueError("El archivo ZIP está dañado.")

            root = staging.resolve()

            for info, relative, kind, is_dir in members:
                target = staging.joinpath(*relative.parts)

                # Verificar que el destino permanezca dentro
                # de la carpeta temporal de extracción.
                if not target.resolve().is_relative_to(root):
                    raise ValueError("Ruta de extracción no permitida.")

                # Crear directorios.
                if is_dir:
                    target.mkdir(parents=True, exist_ok=True)

                else:
                    target.parent.mkdir(parents=True, exist_ok=True)

                    # Extraer archivos sin sobrescribir ninguno existente.
                    with zf.open(info, "r") as source_file:
                        with target.open("xb") as output_file:

                            # Copiar en bloques de 1 MiB.
                            # Evita cargar cada archivo completo en memoria
                            # durante la extracción.
                            while True:
                                chunk = source_file.read(1024 * 1024)

                                if not chunk:
                                    break

                                output_file.write(chunk)

        # Publicar la carpeta recuperada solo si todo salió bien.
        os.rename(staging, dst)
