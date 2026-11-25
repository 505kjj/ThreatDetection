"""Procedural diagnostic inputs. The generated designs are fictional marks."""

from PIL import Image, ImageDraw, ImageEnhance

from vision import encode


def invented_mark(index):
    image = Image.new("RGBA", (420, 112), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    color = ("#516030", "#40500d", "#6c4821", "#595f31")[index]
    if index in (0, 3):
        for x in range(12, 92, 14):
            draw.rectangle((x, 19 + x % 11, x + 10, 90), fill=color)
        draw.polygon([(24, 34), (66, 8), (96, 51), (52, 104)], outline="#26241e", width=5)
    elif index == 1:
        draw.arc((5, 9, 95, 102), 40, 310, fill=color, width=13)
        draw.rectangle((38, 44, 67, 75), fill=color)
    else:
        for offset in range(3):
            draw.polygon([(5 + offset * 24, 88), (29 + offset * 24, 20), (49 + offset * 24, 88)],
                         outline=color, width=5)
    for i in range(7):
        start = 120 + 42 * i
        top = 24 + (index * 3 + i * 13) % 17
        draw.line((start, top, start, 78, start + 24, 78), fill=color, width=7)
        draw.line((start, top, start + (17 if index == 3 else 24), top), fill=color, width=6)
        if (i + index) % 2:
            draw.line((start + 8, 54, start + 25, 54), fill=color, width=5)
    return image


def transformations(image):
    width, height = image.size
    resized = image.resize((max(8, width // 3), max(8, height // 3)), Image.Resampling.LANCZOS)
    white = Image.new("RGB", image.size, "#fff")
    white.paste(image, mask=image.getchannel("A"))
    colored = ImageEnhance.Color(white).enhance(0.30)
    background = Image.new("RGBA", (width + 40, height + 42), "#cad9de")
    background.alpha_composite(image, (20, 21))
    return {
        "resized": encode(resized),
        "jpeg-quality-30": encode(white, "JPEG", quality=30),
        "cropped": encode(image.crop((width // 9, 0, width - width // 15, height))),
        "desaturated": encode(colored),
        "colored-background": encode(background),
        "padded-transparent": encode(padded(image))
    }


def padded(image):
    result = Image.new("RGBA", (image.width + 40, image.height + 42))
    result.alpha_composite(image, (20, 21))
    return result
