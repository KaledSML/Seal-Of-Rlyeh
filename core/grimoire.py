import os
import smtplib
from email.message import EmailMessage
from pathlib import Path
from PIL import Image, ImageDraw

# ---------------------------------------------------------------------------
# Alfabeto de Nug-Soth (Diccionario vectorial 100% fiel a la tabla original)
# ---------------------------------------------------------------------------
GLYPHS = {
    "a": [("poly", [(20, 15), (50, 85), (80, 15)])],
    "b": [("poly", [(20, 15), (80, 15), (80, 85)])],
    "c": [("poly", [(20, 15), (20, 85), (80, 85), (80, 15)])],
    "d": [("poly", [(20, 15), (20, 85), (80, 85)])],
    "e": [("poly", [(80, 15), (20, 15), (20, 85), (80, 85)])],
    "f": [("poly", [(80, 15), (20, 15), (20, 85), (80, 85)])],
    "g": [("rect", 20, 15, 80, 85)],
    "h": [("poly", [(80, 15), (20, 15), (20, 85), (80, 85)])],
    "i": [("poly", [(80, 15), (20, 50), (80, 85)])],
    "j": [("rect", 20, 15, 80, 85), ("dot", 50, 50, 5)],
    "k": [("rect", 20, 15, 80, 85), ("circle", 50, 50, 12)],
    "l": [("poly", [(20, 15), (80, 15), (80, 85)])],
    "m": [("poly", [(20, 85), (20, 15), (80, 15), (80, 85)])],
    "n": [("poly", [(20, 85), (20, 15), (80, 15), (80, 85)]), ("line", 20, 35, 80, 35)],
    "o": [("poly", [(20, 85), (50, 15), (80, 85)])],
    "p": [("poly", [(20, 85), (20, 15), (80, 15)]), ("line", 20, 85, 35, 85), ("dot", 30, 75, 3)],
    "q": [("poly", [(20, 15), (20, 85), (80, 85)]), ("line", 20, 50, 50, 50)],
    "r": [("poly", [(80, 85), (80, 15), (20, 15)]), ("dot", 65, 30, 4)],
    "s": [("poly", [(20, 85), (20, 15), (80, 15)])],
    "t": [("poly", [(20, 85), (20, 15), (80, 15)]), ("dot", 35, 35, 4)],
    "u": [("poly", [(20, 85), (50, 15), (80, 85)]), ("dot", 50, 55, 4)],
    "v": [("poly", [(80, 15), (20, 50), (80, 85)]), ("dot", 65, 50, 4)],
    "w": [("poly", [(20, 15), (20, 85)]), ("poly", [(80, 15), (80, 85)]), ("line", 20, 50, 80, 50)],
    "x": [("poly", [(20, 15), (20, 85), (80, 85), (80, 15)]), ("line", 20, 50, 50, 50)],
    "y": [("poly", [(80, 15), (20, 50), (80, 85)]), ("line", 50, 50, 80, 50)],
    "z": [("poly", [(20, 85), (20, 15), (80, 15)]), ("dot", 35, 30, 4)],
    "0": [("poly", [(50, 15), (85, 50), (50, 85), (15, 50), (50, 15)])],
    "1": [("poly", [(50, 15), (85, 50), (50, 85), (15, 50), (50, 15)]), ("dot", 70, 65, 4)],
    "2": [("poly", [(50, 15), (85, 50), (50, 85), (15, 50), (50, 15)]), ("dot", 65, 35, 4)],
    "3": [("poly", [(50, 15), (85, 50), (50, 85), (15, 50), (50, 15)]), ("dot", 35, 35, 4)],
    "4": [("poly", [(50, 15), (85, 50), (50, 85), (15, 50), (50, 15)]), ("dot", 30, 65, 4)],
    "5": [("poly", [(50, 15), (85, 50), (50, 85), (15, 50), (50, 15)]), ("dot", 50, 50, 4)],
    "6": [("poly", [(50, 15), (85, 50), (50, 85), (15, 50), (50, 15)]), ("dot", 65, 35, 4), ("dot", 35, 65, 4)],
    "7": [("poly", [(50, 15), (85, 50), (50, 85), (15, 50), (50, 15)]), ("dot", 35, 35, 4), ("dot", 65, 65, 4)],
    "8": [("poly", [(50, 15), (85, 50), (50, 85), (15, 50), (50, 15)]), ("dot", 40, 50, 4), ("dot", 60, 50, 4)],
    "9": [("poly", [(50, 15), (85, 50), (50, 85), (15, 50), (50, 15)]), ("dot", 50, 35, 4), ("dot", 50, 65, 4)],
}

def generate_glyph_image(text: str, out_path: str, cell=90, pad=14, bg=(10, 8, 6), fg=(225, 210, 190)):
    chars = [c for c in text.lower() if c in GLYPHS]
    if not chars:
        chars = ["g"]

    width = cell * len(chars) + pad * (len(chars) + 1)
    height = cell + pad * 2
    img = Image.new("RGB", (width, height), color=bg)
    draw = ImageDraw.Draw(img)

    for i, ch in enumerate(chars):
        ox = pad + i * (cell + pad)
        oy = pad
        scale = cell / 100.0
        
        for instr in GLYPHS[ch]:
            kind = instr[0]
            if kind == "line":
                _, x1, y1, x2, y2 = instr
                draw.line([(ox + x1 * scale, oy + y1 * scale), (ox + x2 * scale, oy + y2 * scale)],
                          fill=fg, width=4)
            elif kind == "poly":
                pts = [(ox + x * scale, oy + y * scale) for x, y in instr[1]]
                draw.line(pts, fill=fg, width=4, joint="curve")
            elif kind == "rect":
                _, x1, y1, x2, y2 = instr
                draw.rectangle([ox + x1 * scale, oy + y1 * scale, ox + x2 * scale, oy + y2 * scale],
                               outline=fg, width=4)
            elif kind == "circle":
                _, cx, cy, r = instr
                r = r * scale
                cx, cy = ox + cx * scale, oy + cy * scale
                draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=fg, width=4)
            elif kind == "dot":
                _, cx, cy, r = instr
                r = r * scale
                cx, cy = ox + cx * scale, oy + cy * scale
                draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fg)

    img.save(out_path)
    return out_path

def send_panic_email(sender_email: str, app_password: str, smtp_host: str, attachment_path: str):
    msg = EmailMessage()
    msg["From"] = sender_email
    msg["To"] = sender_email
    msg["Subject"] = "¡Iä! ¡Iä! Cthulhu fhtagn! Alguien intenta profanar el Sello de R'lyeh"
    msg.set_content(
        "Las alarmas ancestrales han resonado. Alguien ha fallado tres veces al intentar "
        "abrir tu cofre protegido.\n\n"
        "El archivo ha sido mudado a una ubicación secreta dentro de tus Documentos.\n"
        "Se adjunta la imagen con los glifos exactos de Nug-Soth que codifican tu contraseña."
    )

    if Path(attachment_path).exists():
        with open(attachment_path, "rb") as f:
            file_data = f.read()
            file_name = Path(attachment_path).name
        msg.add_attachment(file_data, maintype="image", subtype="png", filename=file_name)

    with smtplib.SMTP_SSL(smtp_host, 465) as server:
        server.login(sender_email, app_password)
        server.send_message(msg)