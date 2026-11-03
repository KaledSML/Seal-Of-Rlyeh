
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from rlyeh_crypto import encrypt_file
from rlyeh_vault import seal_path, open_container


class TestVault(unittest.TestCase):

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)

        self.source = self.root / "documentos"
        self.source.mkdir()

        (self.source / "nota.txt").write_text(
            "El sello de R'lyeh permanece cerrado.",
            encoding="utf-8",
        )

        (self.source / "subcarpeta").mkdir()

        (self.source / "subcarpeta" / "secreto.txt").write_text(
            "Nug-Soth",
            encoding="utf-8",
        )

        self.container = self.root / "prueba.rlyeh"
        self.recovered = self.root / "recuperado"
        self.rejected = self.root / "no_deberia_existir"

        self.password = "Prueba-Rlyeh-938!"

    def tearDown(self):
        self.temp.cleanup()

    def test_folder_is_sealed_and_original_is_preserved(self):
        seal_path(
            self.source,
            self.container,
            self.password,
        )

        self.assertTrue(self.source.exists())
        self.assertTrue(self.container.is_file())

    def test_wrong_password_is_rejected(self):
        seal_path(
            self.source,
            self.container,
            self.password,
        )

        with self.assertRaisesRegex(ValueError, "Contraseña incorrecta"):
            open_container(
                str(self.container),
                str(self.rejected),
                "contraseña-incorrecta",
            )

        self.assertFalse(self.rejected.exists())

    def test_files_and_subfolders_are_recovered(self):
        seal_path(
            self.source,
            self.container,
            self.password,
        )

        open_container(
            str(self.container),
            str(self.recovered),
            self.password,
        )

        recovered_note = (
            self.recovered / "documentos" / "nota.txt"
        )

        original_note = self.source / "nota.txt"

        recovered_secret = (
            self.recovered
            / "documentos"
            / "subcarpeta"
            / "secreto.txt"
        )

        self.assertEqual(
            recovered_note.read_text(encoding="utf-8"),
            original_note.read_text(encoding="utf-8"),
        )

        self.assertEqual(
            recovered_secret.read_text(encoding="utf-8"),
            "Nug-Soth",
        )

    def test_single_file_is_sealed_and_recovered(self):
        original_file = self.root / "individual.txt"
        container = self.root / "individual.rlyeh"
        output = self.root / "salida"

        original_content = "Un archivo individual bajo el sello."
        original_file.write_text(original_content, encoding="utf-8")

        seal_path(
            original_file,
            container,
            self.password,
        )

        self.assertTrue(original_file.exists())
        self.assertTrue(container.is_file())

        open_container(
            container,
            output,
            self.password,
        )

        recovered_file = output / "individual.txt"

        self.assertEqual(
            original_content,
            recovered_file.read_text(encoding="utf-8"),
        )

    def test_existing_destination_is_not_overwritten(self):
        self.container.write_bytes(b"CONTENIDO ORIGINAL")

        with self.assertRaises(FileExistsError):
            seal_path(
                self.source,
                self.container,
                self.password,
            )

        self.assertEqual(
            self.container.read_bytes(),
            b"CONTENIDO ORIGINAL",
        )

    def test_nonexistent_source_is_rejected(self):
        missing_source = self.root / "no_existe.txt"

        with self.assertRaisesRegex(
            ValueError,
            "El origen no existe",
        ):
            seal_path(
                missing_source,
                self.container,
                self.password,
            )

        self.assertFalse(self.container.exists())

    def test_path_traversal_is_rejected(self):
        malicious_zip = self.root / "malicioso.zip"
        malicious_container = self.root / "malicioso.rlyeh"

        escaped_file = self.root / "archivo_fuera.txt"
        output = self.root / "recuperacion_maliciosa"

        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr(
                "../archivo_fuera.txt",
                "Este archivo no debería extraerse.",
            )

        encrypt_file(
            str(malicious_zip),
            str(malicious_container),
            self.password,
        )

        with self.assertRaisesRegex(
            ValueError,
            "ruta peligrosa",
        ):
            open_container(
                malicious_container,
                output,
                self.password,
            )

        self.assertFalse(output.exists())
        self.assertFalse(escaped_file.exists())

    def test_duplicate_zip_entries_are_rejected(self):
        malicious_zip = self.root / "duplicado.zip"
        malicious_container = self.root / "duplicado.rlyeh"
        output = self.root / "recuperacion_duplicada"

        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr("nota.txt", "Primera versión")
            zf.writestr("nota.txt", "Segunda versión")

        encrypt_file(
            str(malicious_zip),
            str(malicious_container),
            self.password,
        )

        with self.assertRaisesRegex(
            ValueError,
            "rutas duplicadas",
        ):
            open_container(
                malicious_container,
                output,
                self.password,
            )

        self.assertFalse(output.exists())

    def test_file_size_limit_is_enforced(self):
        malicious_zip = self.root / "grande.zip"
        malicious_container = self.root / "grande.rlyeh"
        output = self.root / "recuperacion_grande"

        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr("archivo.txt", b"123456")

        encrypt_file(
            str(malicious_zip),
            str(malicious_container),
            self.password,
        )

        # Reducimos el límite a 5 bytes solo durante esta prueba.
        with patch("rlyeh_vault.MAX_FILE_SIZE", 5):
            with self.assertRaisesRegex(
                ValueError,
                "Un archivo supera el límite permitido",
            ):
                open_container(
                    malicious_container,
                    output,
                    self.password,
                )

        self.assertFalse(output.exists())

    def test_total_size_limit_is_enforced(self):
        malicious_zip = self.root / "total_grande.zip"
        malicious_container = self.root / "total_grande.rlyeh"
        output = self.root / "recuperacion_total_grande"

        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr("archivo1.txt", b"123")
            zf.writestr("archivo2.txt", b"456")

        encrypt_file(
            str(malicious_zip),
            str(malicious_container),
            self.password,
        )

        # Reducimos el límite total a 5 bytes solo durante esta prueba.
        with patch("rlyeh_vault.MAX_TOTAL_SIZE", 5):
            with self.assertRaisesRegex(
                ValueError,
                "El contenido supera el límite de extracción",
            ):
                open_container(
                    malicious_container,
                    output,
                    self.password,
                )

        self.assertFalse(output.exists())

    def test_reserved_windows_names_are_rejected(self):
        malicious_zip = self.root / "reservado.zip"
        malicious_container = self.root / "reservado.rlyeh"
        output = self.root / "recuperacion_reservada"

        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr("CON.txt", "Nombre reservado")

        encrypt_file(
            str(malicious_zip),
            str(malicious_container),
            self.password,
        )

        with self.assertRaisesRegex(
            ValueError,
            "Nombre de archivo reservado en Windows",
        ):
            open_container(
                malicious_container,
                output,
                self.password,
            )

        self.assertFalse(output.exists())

    def test_case_insensitive_duplicate_names_are_rejected(self):
        malicious_zip = self.root / "colision.zip"
        malicious_container = self.root / "colision.rlyeh"
        output = self.root / "recuperacion_colision"

        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr("Nota.txt", "Primera versión")
            zf.writestr("nota.txt", "Segunda versión")

        encrypt_file(
            str(malicious_zip),
            str(malicious_container),
            self.password,
        )

        with self.assertRaisesRegex(
            ValueError,
            "rutas duplicadas",
        ):
            open_container(
                malicious_container,
                output,
                self.password,
            )

        self.assertFalse(output.exists())

    def test_windows_trailing_dot_and_space_names_are_rejected(self):
        malicious_zip = self.root / "punto_espacio.zip"
        malicious_container = self.root / "punto_espacio.rlyeh"
        output = self.root / "recuperacion_punto_espacio"

        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr("secreto.txt.", "Archivo con punto final")
            zf.writestr("secreto.txt ", "Archivo con espacio final")

        encrypt_file(
            str(malicious_zip),
            str(malicious_container),
            self.password,
        )

        with self.assertRaisesRegex(
            ValueError,
            "Nombre de archivo",
        ):
            open_container(
                malicious_container,
                output,
                self.password,
            )

        self.assertFalse(output.exists())

    def test_symbolic_links_are_rejected(self):
        malicious_zip = self.root / "symlink.zip"
        malicious_container = self.root / "symlink.rlyeh"
        output = self.root / "recuperacion_symlink"

        # Creamos una entrada ZIP marcada como enlace simbólico.
        symlink_info = zipfile.ZipInfo("enlace.txt")
        symlink_info.create_system = 3
        symlink_info.external_attr = (0o120777 << 16)

        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr(symlink_info, "C:/archivo_externo.txt")

        encrypt_file(
            str(malicious_zip),
            str(malicious_container),
            self.password,
        )

        with self.assertRaisesRegex(
            ValueError,
            "Tipo de archivo no permitido",
        ):
            open_container(
                malicious_container,
                output,
                self.password,
            )

        self.assertFalse(output.exists())

    def test_invalid_zip_content_is_rejected(self):
        invalid_data = self.root / "no_es_un_zip.bin"
        invalid_container = self.root / "no_es_un_zip.rlyeh"
        output = self.root / "recuperacion_invalida"

        invalid_data.write_bytes(
            b"Esto no contiene una estructura ZIP valida."
        )

        encrypt_file(
            str(invalid_data),
            str(invalid_container),
            self.password,
        )

        with self.assertRaises(zipfile.BadZipFile):
            open_container(
                invalid_container,
                output,
                self.password,
            )

        self.assertFalse(output.exists())

    def test_member_limit_is_enforced(self):
        malicious_zip = self.root / "muchas_entradas.zip"
        malicious_container = self.root / "muchas_entradas.rlyeh"
        output = self.root / "recuperacion_muchas_entradas"

        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr("archivo1.txt", "Primero")
            zf.writestr("archivo2.txt", "Segundo")
            zf.writestr("archivo3.txt", "Tercero")

        encrypt_file(
            str(malicious_zip),
            str(malicious_container),
            self.password,
        )

        # Reducimos el límite a 2 entradas durante esta prueba.
        with patch("rlyeh_vault.MAX_MEMBERS", 2):
            with self.assertRaisesRegex(
                ValueError,
                "El contenedor contiene demasiados archivos",
            ):
                open_container(
                    malicious_container,
                    output,
                    self.password,
                )

        self.assertFalse(output.exists())

    def test_corrupted_zip_crc_is_rejected(self):
        damaged_zip = self.root / "danado.zip"
        damaged_container = self.root / "danado.rlyeh"
        output = self.root / "recuperacion_danada"

        with zipfile.ZipFile(damaged_zip, "w") as zf:
            zf.writestr("nota.txt", "Este contenido será alterado.")

        # Alteramos un byte de los datos internos del ZIP.
        with zipfile.ZipFile(damaged_zip, "r") as zf:
            info = zf.getinfo("nota.txt")
            data_position = info.header_offset + 30
            data_position += len(info.filename.encode("utf-8"))
            data_position += len(info.extra)

        with damaged_zip.open("r+b") as file:
            file.seek(data_position)
            original_byte = file.read(1)
            file.seek(data_position)
            file.write(bytes([original_byte[0] ^ 0xFF]))

        encrypt_file(
            str(damaged_zip),
            str(damaged_container),
            self.password,
        )

        with self.assertRaisesRegex(
            ValueError,
            "El archivo ZIP está dañado",
        ):
            open_container(
                damaged_container,
                output,
                self.password,
            )

        self.assertFalse(output.exists())

    def test_folder_can_be_sealed_recovered_and_sealed_again(self):
        first_container = self.root / "primero.rlyeh"
        first_recovery = self.root / "primera_recuperacion"

        second_container = self.root / "segundo.rlyeh"
        second_recovery = self.root / "segunda_recuperacion"

        seal_path(
            self.source,
            first_container,
            self.password,
        )

        open_container(
            first_container,
            first_recovery,
            self.password,
        )

        recovered_folder = first_recovery / "documentos"

        seal_path(
            recovered_folder,
            second_container,
            self.password,
        )

        open_container(
            second_container,
            second_recovery,
            self.password,
        )

        second_folder = second_recovery / "documentos"

        self.assertEqual(
            (self.source / "nota.txt").read_bytes(),
            (second_folder / "nota.txt").read_bytes(),
        )

        self.assertEqual(
            (self.source / "subcarpeta" / "secreto.txt").read_bytes(),
            (second_folder / "subcarpeta" / "secreto.txt").read_bytes(),
        )

if __name__ == "__main__":
    unittest.main()
