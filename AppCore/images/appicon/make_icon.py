"""
Генератор иконки AllPass.

Концепция A (основная): навесной замок с замочной скважиной, «вырезанной» до фона,
на тёмно-синем скруглённом квадрате. Скважина просвечивает градиентом — знак
читается и в 16 px, и в 256 px, без мелких деталей.

Концепции B и C — альтернативы для сравнения (щит и ключ).

Запуск:  python make_icon.py
Результат: PNG 16..256, allpass.ico (мультиразмерный), preview.png
"""

from __future__ import annotations

import io
import os

from PIL import Image, ImageChops, ImageDraw, ImageFilter

OUT = os.path.dirname(os.path.abspath(__file__))
SS = 1024          # супер-сэмплинг
MASTER = 256       # логическая сетка геометрии

# --- палитра ---------------------------------------------------------------
BG_TOP = (30, 78, 121)        # #1E4E79
BG_BOTTOM = (11, 33, 51)      # #0B2133
LOCK = (236, 246, 255)        # #ECF6FF
RIM = (255, 255, 255, 70)
SHADOW = (0, 8, 16, 105)

# --- пропорции замка (доли сетки 256) --------------------------------------
P = dict(
    body=(0.215, 0.785, 0.468, 0.822),
    body_r=0.062,
    shackle_r=0.185,
    shackle_w=0.080,
    hole=(0.500, 0.628),
    hole_r=0.048,
    stem_top=0.030,
    stem_bot=0.045,
    stem_bottom=0.742,
)

P_COMPACT = dict(
    body=(0.205, 0.795, 0.462, 0.826),
    body_r=0.068,
    shackle_r=0.188,
    shackle_w=0.096,
    hole=(0.500, 0.622),
    hole_r=0.062,
    stem_top=0.041,
    stem_bot=0.058,
    stem_bottom=0.742,
)


def lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def gradient(size: int) -> Image.Image:
    """Диагональный градиент: строим малым и растягиваем — без бандинга."""
    small = 256
    img = Image.new("RGB", (small, small))
    px = img.load()
    for y in range(small):
        for x in range(small):
            px[x, y] = lerp(BG_TOP, BG_BOTTOM, (x + y) / (2 * (small - 1)))
    return img.resize((size, size), Image.Resampling.BICUBIC)


def s(f: float) -> float:
    """Доля сетки 256 -> пиксели супер-сэмплинга."""
    return f * MASTER * (SS / MASTER)


# --- концепция A: замок -----------------------------------------------------
def lock_masks(patch: dict | None = None):
    p = dict(P)
    if patch:
        p.update(patch)
    k = SS / MASTER
    lock = Image.new("L", (SS, SS), 0)
    d = ImageDraw.Draw(lock)

    # дужка: полукольцо + ножки, уходящие в корпус
    cx, cy = s(0.5), s(p["body"][2])
    r = s(p["shackle_r"])
    sw = s(p["shackle_w"])
    d.arc([cx - r, cy - r, cx + r, cy + r], 180, 360, fill=255, width=round(sw))
    # ножки начинаются ровно от плоскости среза дуги, иначе над корпусом
    # появляются «уши» там, где скругление корпуса уходит вниз
    for lx in (cx - r, cx + r):
        d.rectangle([lx - sw / 2, cy, lx + sw / 2, cy + s(0.05)], fill=255)

    # корпус
    bx0, bx1, by0, by1 = (s(v) for v in p["body"])
    d.rounded_rectangle([bx0, by0, bx1, by1], radius=s(p["body_r"]), fill=255)

    # скважина
    hole = Image.new("L", (SS, SS), 0)
    hd = ImageDraw.Draw(hole)
    hx, hy = s(p["hole"][0]), s(p["hole"][1])
    hr = s(p["hole_r"])
    hd.ellipse([hx - hr, hy - hr, hx + hr, hy + hr], fill=255)
    if p["stem_bot"] > 0:
        top, bot = s(p["stem_top"]), s(p["stem_bot"])
        hb = s(p["stem_bottom"])
        hd.polygon(
            [(hx - top, hy), (hx + top, hy), (hx + bot, hb), (hx - bot, hb)], fill=255
        )
        hd.ellipse([hx - bot, hb - bot, hx + bot, hb + bot], fill=255)

    return ImageChops.subtract(lock, hole)


def draw_main(patch: dict | None = None) -> Image.Image:
    k = SS / MASTER
    icon = Image.new("RGBA", (SS, SS), (0, 0, 0, 0))

    radius = s(0.225)
    shape = Image.new("L", (SS, SS), 0)
    ImageDraw.Draw(shape).rounded_rectangle([0, 0, SS - 1, SS - 1], radius=radius, fill=255)
    icon.paste(gradient(SS).convert("RGBA"), (0, 0), shape)

    mask = lock_masks(patch)

    # мягкая тень под замком
    sh = mask.filter(ImageFilter.GaussianBlur(s(0.028)))
    sh = ImageChops.offset(sh, 0, int(s(0.016)))
    shadow = Image.new("RGBA", (SS, SS), SHADOW)
    shadow.putalpha(ImageChops.multiply(sh, Image.new("L", (SS, SS), SHADOW[3])))
    icon.alpha_composite(
        Image.composite(shadow, Image.new("RGBA", (SS, SS), (0, 0, 0, 0)), shape)
    )

    icon.paste(LOCK + (255,), (0, 0), mask)

    # тонкий светлый кант
    rim = Image.new("RGBA", (SS, SS), (0, 0, 0, 0))
    rw = max(2, round(s(0.007)))
    ImageDraw.Draw(rim).rounded_rectangle(
        [rw / 2, rw / 2, SS - 1 - rw / 2, SS - 1 - rw / 2],
        radius=radius - rw / 2,
        outline=RIM,
        width=rw,
    )
    icon.alpha_composite(rim)
    return icon


# --- концепция B: щит -------------------------------------------------------
def shield_mask():
    shield = Image.new("L", (SS, SS), 0)
    d = ImageDraw.Draw(shield)

    top, side = s(0.14), s(0.62)
    left, right = s(0.14), s(0.86)
    tip = s(0.90)
    mid = (left + right) / 2
    pts = [(left, top), (right, top), (right, side)]
    for i in range(1, 41):
        t = i / 40
        pts.append((right + (mid - right) * t, side + (tip - side) * (t**1.65)))
    for i in range(1, 41):
        t = i / 40
        pts.append((mid + (left - mid) * t, tip + (side - tip) * (t**1.65)))
    d.polygon(pts, fill=255)

    hole = Image.new("L", (SS, SS), 0)
    hd = ImageDraw.Draw(hole)
    hx, hy = s(0.5), s(0.44)
    hr = s(0.055)
    hd.ellipse([hx - hr, hy - hr, hx + hr, hy + hr], fill=255)
    hd.polygon(
        [
            (hx - s(0.032), hy),
            (hx + s(0.032), hy),
            (hx + s(0.052), s(0.60)),
            (hx - s(0.052), s(0.60)),
        ],
        fill=255,
    )
    hd.ellipse([hx - s(0.052), s(0.60) - s(0.052), hx + s(0.052), s(0.60) + s(0.052)], fill=255)
    return ImageChops.subtract(shield, hole)


# --- концепция C: ключ ------------------------------------------------------
def key_mask():
    key = Image.new("L", (SS, SS), 0)
    d = ImageDraw.Draw(key)
    hole = Image.new("L", (SS, SS), 0)
    hd = ImageDraw.Draw(hole)

    cx, cy = s(0.5), s(0.315)
    r_out, r_in = s(0.180), s(0.082)
    d.ellipse([cx - r_out, cy - r_out, cx + r_out, cy + r_out], fill=255)
    hd.ellipse([cx - r_in, cy - r_in, cx + r_in, cy + r_in], fill=255)

    sw = s(0.100)
    d.rectangle([cx - sw / 2, cy + r_out - s(0.02), cx + sw / 2, s(0.825)], fill=255)
    tooth_w = s(0.150)
    for ty, th in ((0.700, 0.062), (0.790, 0.055)):
        d.rectangle([cx + sw / 2, s(ty), cx + sw / 2 + tooth_w, s(ty + th)], fill=255)
    hd.rectangle([cx - s(0.026), cy + r_out + s(0.02), cx + s(0.026), s(0.655)], fill=255)
    return ImageChops.subtract(key, hole)


# --- растеризация -----------------------------------------------------------
def render(concept: str, size: int, patch: dict | None = None) -> Image.Image:
    if concept == "a_lock":
        master = draw_main(patch)
    else:
        master = Image.new("RGBA", (SS, SS), (0, 0, 0, 0))
        master.paste(LOCK + (255,), (0, 0), shield_mask() if concept == "b_shield" else key_mask())
    return master.resize((size, size), Image.Resampling.LANCZOS)


def params_for(size: int) -> dict | None:
    if size <= 20:
        # совсем мелкий размер: скважина — только точка, иначе она превращается в кашу
        return dict(P_COMPACT, stem_bot=0.0, hole_r=0.082, shackle_w=0.105)
    if size <= 32:
        return P_COMPACT
    return None


def write_ico(path: str, frames: list[tuple[int, Image.Image]]) -> None:
    """ICO с PNG-нагрузкой (Windows Vista+)."""
    blobs = []
    for size, img in frames:
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        blobs.append((size, buf.getvalue()))

    header = b"\x00\x00\x01\x00" + len(blobs).to_bytes(2, "little")
    offset = 6 + 16 * len(blobs)
    entries, data = b"", b""
    for size, blob in blobs:
        dim = 0 if size >= 256 else size
        entries += bytes([dim, dim, 0, 0])
        entries += (1).to_bytes(2, "little") + (32).to_bytes(2, "little")
        entries += len(blob).to_bytes(4, "little") + offset.to_bytes(4, "little")
        offset += len(blob)
        data += blob
    with open(path, "wb") as f:
        f.write(header + entries + data)


# --- превью -----------------------------------------------------------------
def make_preview() -> None:
    from PIL import ImageFont

    def font(px, bold=False):
        path = r"C:\Windows\Fonts\seguisb.ttf" if bold else r"C:\Windows\Fonts\segoeui.ttf"
        try:
            return ImageFont.truetype(path, px)
        except OSError:
            return ImageFont.load_default()

    W = 1120
    sizes = [16, 20, 24, 32, 48, 64, 96, 128]
    H = 1040
    sheet = Image.new("RGB", (W, H), "#F4F6F9")
    d = ImageDraw.Draw(sheet)

    # --- тёмная шапка: три концепции
    d.rectangle([0, 0, W, 300], fill="#1B1F24")
    d.text((56, 40), "AllPass — варианты иконки", font=font(34, True), fill="#FFFFFF")
    d.text((56, 92), "A — рекомендую: замок, скважина вырезана до фона", font=font(20), fill="#B8C6D4")

    x = 56
    for concept, label, sub in (
        ("a_lock", "A. Замок", "основная"),
        ("b_shield", "B. Щит", "альтернатива"),
        ("c_key", "C. Ключ", "альтернатива"),
    ):
        icon = render(concept, 128)
        sheet.paste(icon, (x, 140), icon)
        d.text((x + 152, 176), label, font=font(24, True), fill="#FFFFFF")
        d.text((x + 152, 210), sub, font=font(18), fill="#8FA3B6")
        x += 340

    # --- светлая часть: реальные размеры
    d.text((56, 332), "Вариант A в реальных размерах", font=font(20, True), fill="#1B2733")
    cell = 128
    x, base = 40, 486
    for size in sizes:
        icon = render("a_lock", size, params_for(size))
        sheet.paste(icon, (x + (cell - size) // 2, base - size), icon)
        d.text((x + cell // 2 - 14, base + 12), f"{size}", font=font(17), fill="#5A6B7B")
        x += cell

    # --- увеличенный контроль 16/24
    d.text((56, 552), "Контроль мелких размеров (увеличено ×5, без сглаживания)",
           font=font(20, True), fill="#1B2733")
    x = 56
    for size in (16, 24, 32):
        small = render("a_lock", size, params_for(size))
        zoom = small.resize((size * 5, size * 5), Image.Resampling.NEAREST)
        sheet.paste(zoom, (x, 596), zoom)
        d.text((x, 596 + size * 5 + 10), f"{size}px", font=font(17), fill="#5A6B7B")
        x += size * 5 + 60

    # --- тёмная тема
    d.rectangle([0, 830, W, H], fill="#1B1F24")
    d.text((56, 856), "Вариант A на тёмной теме", font=font(20, True), fill="#FFFFFF")
    x, y = 56, 894
    for size in sizes:
        icon = render("a_lock", size, params_for(size))
        sheet.paste(icon, (x, y + (112 - size) // 2), icon)
        x += max(size, 48) + 30

    sheet.save(os.path.join(OUT, "preview.png"))


def main() -> None:
    os.makedirs(OUT, exist_ok=True)

    sizes = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
    frames = []
    for size in sizes:
        img = render("a_lock", size, params_for(size))
        img.save(os.path.join(OUT, f"allpass_{size}.png"))
        frames.append((size, img))
    write_ico(os.path.join(OUT, "allpass.ico"), frames)

    for concept in ("b_shield", "c_key"):
        render(concept, 256).save(os.path.join(OUT, f"variant_{concept}_256.png"))

    make_preview()


if __name__ == "__main__":
    main()
    print("Готово:", OUT)
