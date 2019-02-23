import struct

def rc4Decrypt(data, key):
    """RC4 algorithm"""
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + int(box[i]) + int(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(int(char) ^ box[(box[x] + box[y]) % 256]))

    return ''.join(out)

def rawbytes(s):
    """Convert a string to raw bytes without encoding"""
    outlist = []
    for cp in s:
        num = ord(cp)
        if num < 255:
            outlist.append(struct.pack('B', num))
        elif num < 65535:
            outlist.append(struct.pack('>H', num))
        else:
            b = (num & 0xFF0000) >> 16
            H = num & 0xFFFF
            outlist.append(struct.pack('>bH', b, H))
    return b''.join(outlist)

def RC4Encrypt(key, data):
    S = list(range(256))
    j = 0

    for i in list(range(256)):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    j = 0
    y = 0
    out = []

    for char in data:
        j = (j + 1) % 256
        y = (y + S[j]) % 256
        S[j], S[y] = S[y], S[j]
        out.append(chr(ord(char) ^ S[(S[j] + S[y]) % 256]))
    return ''.join(out).rstrip('\0')
