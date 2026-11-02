
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

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


if __name__ == "__main__":
    unittest.main()
