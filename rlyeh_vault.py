
from pathlib import Path, PurePosixPath
import os
import stat
import tempfile
import zipfile

from rlyeh_crypto import encrypt_file, decrypt_file


MAX_MEMBERS = 10_000
MAX_FILE_SIZE = 512 * 1024 * 1024
MAX_TOTAL_SIZE = 2 * 1024 * 1024 * 1024


def seal_path(source, destination, password):
    original = Path(source)

    if original.is_symlink() or not original.exists():
        raise ValueError("El origen no existe o es un enlace simbólico.")

    src = original.resolve()
    dst = Path(destination).resolve()

    if not (src.is_file() or src.is_dir()):
        raise ValueError("El origen debe ser un archivo o una carpeta.")
    if dst.exists():
        raise FileExistsError(f"El destino ya existe: {dst}")
    if src == dst or (src.is_dir() and src in dst.parents):
        raise ValueError("El contenedor no puede estar dentro del origen.")

    dst.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(dir=dst.parent) as work:
        work = Path(work)
        archive = work / "payload.zip"
        encrypted = work / "payload.rlyeh"

        with zipfile.ZipFile(
            archive, "w", compression=zipfile.ZIP_DEFLATED
        ) as zf:
            paths = [src]
            if src.is_dir():
                paths.extend(sorted(src.rglob("*")))

            for item in paths:
                if item.is_symlink():
                    raise ValueError(
                        f"No se admiten enlaces simbólicos: {item}"
                    )

                relative = (
                    Path(src.name)
                    if item == src
                    else Path(src.name) / item.relative_to(src)
                )
                name = relative.as_posix()

                if item.is_dir():
                    zf.writestr(name.rstrip("/") + "/", b"")
                elif item.is_file():
                    zf.write(item, name)

        encrypt_file(str(archive), str(encrypted), password)

        # No sobrescribe un destino que ya exista.
        os.rename(encrypted, dst)


def _safe_members(zf):
    members = []
    seen = {}
    total_size = 0
    infos = zf.infolist()

    if len(infos) > MAX_MEMBERS:
        raise ValueError("El contenedor contiene demasiados archivos.")

    for info in infos:
        name = info.filename

        if (
            not name
            or "\\" in name
            or name.startswith("/")
            or "\x00" in name
        ):
            raise ValueError("Ruta insegura dentro del contenedor.")

        path = PurePosixPath(name)

        if path.is_absolute() or not path.parts:
            raise ValueError("El contenedor contiene una ruta peligrosa.")

        parts = name.rstrip("/").split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise ValueError("El contenedor contiene una ruta peligrosa.")

        # Evita unidades, rutas especiales y flujos alternativos de Windows.
        if any(":" in part for part in parts):
            raise ValueError("Ruta o unidad no permitida.")

        # Evita nombres de dispositivos reservados en Windows.
        reserved = {
            "CON", "PRN", "AUX", "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }
        for part in parts:
            stem = part.split(".")[0].upper()
            if stem in reserved:
                raise ValueError("Nombre de archivo reservado en Windows.")

        if info.flag_bits & 1:
            raise ValueError("No se admiten entradas ZIP cifradas.")

        if info.file_size < 0 or info.file_size > MAX_FILE_SIZE:
            raise ValueError("Un archivo supera el límite permitido.")

        total_size += info.file_size
        if total_size > MAX_TOTAL_SIZE:
            raise ValueError("El contenido supera el límite de extracción.")

        mode = (info.external_attr >> 16) & 0xFFFF
        kind = stat.S_IFMT(mode)

        if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise ValueError("Tipo de archivo no permitido.")

        is_dir = info.is_dir() or kind == stat.S_IFDIR
        normalized = path.as_posix().rstrip("/")

        if normalized in seen:
            raise ValueError("El contenedor contiene rutas duplicadas.")

        seen[normalized] = is_dir
        members.append((info, path, kind, is_dir))

    # Ningún archivo puede ser padre de otra entrada.
    for _, path, _, _ in members:
        parts = path.parts
        for i in range(1, len(parts)):
            parent = PurePosixPath(*parts[:i]).as_posix()
            if seen.get(parent) is False:
                raise ValueError(
                    "Un archivo del contenedor contiene otras rutas."
                )

    return members


def open_container(container, output_dir, password):
    original = Path(container)

    if original.is_symlink() or not original.is_file():
        raise FileNotFoundError("No existe un contenedor válido.")

    src = original.resolve()
    dst = Path(output_dir).resolve()

    if dst.exists():
        raise FileExistsError(
            f"La carpeta de salida ya existe: {dst}"
        )

    dst.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(dir=dst.parent) as work:
        work = Path(work)
        archive = work / "payload.zip"
        staging = work / "extracted"
        staging.mkdir()

        decrypt_file(str(src), str(archive), password)

        with zipfile.ZipFile(archive, "r") as zf:
            members = _safe_members(zf)

            if zf.testzip() is not None:
                raise ValueError("El archivo ZIP está dañado.")

            root = staging.resolve()

            for info, relative, kind, is_dir in members:
                target = staging.joinpath(*relative.parts)

                # Comprueba el destino completo, no solo su padre.
                if not target.resolve().is_relative_to(root):
                    raise ValueError("Ruta de extracción no permitida.")

                if is_dir:
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)

                    with zf.open(info, "r") as source_file:
                        with target.open("xb") as output_file:
                            while True:
                                chunk = source_file.read(1024 * 1024)
                                if not chunk:
                                    break
                                output_file.write(chunk)

        # Publica la carpeta completa solo tras extraer correctamente.
        os.rename(staging, dst)
