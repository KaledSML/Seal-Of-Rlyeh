
from PIL import Image, ImageChops, ImageFilter
import random
import sys

WIDTH = 90
THRESHOLD = 180

DOTS = (
    (0, 0, 0x01), (0, 1, 0x02),
    (0, 2, 0x04), (0, 3, 0x40),
    (1, 0, 0x08), (1, 1, 0x10),
    (1, 2, 0x20), (1, 3, 0x80),
)


def render_braille(filename):
    image = Image.open(filename).convert("L")

    # Recortar el fondo blanco alrededor de la cimitarra.
    background = Image.new("L", image.size, 255)
    difference = ImageChops.difference(image, background)
    bbox = difference.point(lambda p: 255 if p > 25 else 0).getbbox()

    if bbox:
        image = image.crop(bbox)

    # Engrosar trazos negros para que sobrevivan al Braille.
    image = image.filter(ImageFilter.MinFilter(3))

    pixel_width = WIDTH * 2
    pixel_height = max(
        4,
        round(image.height * pixel_width / image.width / 4) * 4
    )

    image = image.resize(
        (pixel_width, pixel_height),
        Image.Resampling.LANCZOS
    )

    pixels = image.load()
    rng = random.Random(3301)
    rows = []

    for y in range(0, pixel_height, 4):
        line = []

        for x in range(0, pixel_width, 2):
            mask = 0

            for dx, dy, bit in DOTS:
                if pixels[x + dx, y + dy] < THRESHOLD:
                    mask |= bit

            char = chr(0x2800 + mask)

            # Interferencias muy ocasionales, solo en trazos.
            if mask and rng.random() < 0.003:
                char = rng.choice("░▒▓")

            line.append(char)

        rows.append("".join(line).rstrip())

    print("\n".join(rows))


if __name__ == "__main__":
    filename = sys.argv[1] if len(sys.argv) > 1 else "cimitarra.webp"

    print("       ░▒▓ SEAL OF R'LYEH ▓▒░\n")
    render_braille(filename)
    print("\n       [ BARZAI.EXE // SIGNAL CORRUPTED ]")

