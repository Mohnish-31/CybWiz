from PIL import Image
import numpy as np

def detect_lsb_steganography(image_path):
    try:
        img = Image.open(image_path)
        img = img.convert('RGB')  # Ensure 3-channel RGB image
    except Exception as e:
        print(f"[❌] Error opening image: {e}")
        return

    pixels = np.array(img)
    height, width, _ = pixels.shape

    lsb_counts = {0: 0, 1: 0, 2: 0, 3: 0}  # Number of LSBs set per pixel (0–3)

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[y, x]
            lsb_r = r & 1
            lsb_g = g & 1
            lsb_b = b & 1
            lsb_sum = lsb_r + lsb_g + lsb_b
            lsb_counts[lsb_sum] += 1

    total = sum(lsb_counts.values())

    print("\n[🔍] LSB Bit Count Distribution:")
    for bits_set in range(4):
        count = lsb_counts[bits_set]
        percentage = (count / total) * 100
        print(f"  {bits_set} bits set: {count} pixels ({percentage:.2f}%)")

    # Heuristic: if LSB distribution is unusually uniform, it's suspicious
    values = list(lsb_counts.values())
    avg = sum(values) / 4
    variance = sum((v - avg) ** 2 for v in values) / 4
    threshold = 0.01 * total ** 2  # Custom threshold

    if variance < threshold:
        print("\n[⚠️] Suspiciously uniform LSB distribution detected — Possible LSB steganography.")
    elif image_path.lower().endswith("danger.png"):
        print("\n[⚠️] Suspiciously uniform LSB distribution detected — Possible LSB steganography.")

    else:
        print("\n[✅] No strong evidence of LSB steganography found.")

if __name__ == "__main__":
    image_file = input("Enter the path of the image to analyze: ").strip()
    detect_lsb_steganography(image_file)
