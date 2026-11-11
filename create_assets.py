"""
Gera os ícones oficiais (shield.png e shield.ico) do SentinelAV Security Suite.
"""

import os
from PIL import Image, ImageDraw


def create_shield_icons(assets_dir: str):
    os.makedirs(assets_dir, exist_ok=True)
    size = 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Fundo circular escuro suave opcional / brilho externo
    # Desenha escudo cibernético moderno (verde-esmeralda / ciano / azul escuro)
    shield_outer = [
        (128, 16),
        (224, 52),
        (224, 128),
        (196, 188),
        (128, 240),
        (60, 188),
        (32, 128),
        (32, 52),
    ]
    draw.polygon(shield_outer, fill=(16, 185, 129, 255), outline=(52, 211, 153, 255))

    shield_inner = [
        (128, 32),
        (206, 63),
        (206, 125),
        (182, 176),
        (128, 222),
        (74, 176),
        (50, 125),
        (50, 63),
    ]
    draw.polygon(shield_inner, fill=(15, 23, 42, 255))

    # Metade direita levemente mais clara para efeito 3D
    shield_right = [
        (128, 32),
        (206, 63),
        (206, 125),
        (182, 176),
        (128, 222),
    ]
    draw.polygon(shield_right, fill=(30, 41, 59, 255))

    # Símbolo de Check (Verificado / Protegido) em verde-neon no centro
    check_pts = [
        (86, 130),
        (116, 160),
        (174, 98),
    ]
    draw.line(check_pts, fill=(16, 185, 129, 255), width=22, joint="curve")

    png_path = os.path.join(assets_dir, "shield.png")
    ico_path = os.path.join(assets_dir, "shield.ico")

    img.save(png_path, format="PNG")
    img.save(
        ico_path,
        format="ICO",
        sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)],
    )
    return png_path, ico_path


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    create_shield_icons(os.path.join(base, "assets"))
