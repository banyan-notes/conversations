#!/usr/bin/env python3
"""Change the Versatiles site password.

  OLD_PASSWORD=... NEW_PASSWORD=... python3 tools/rekey.py

Re-encrypts the page, every photo/video/music file and the names map with a
key from the new password (new random salt). Checks everything opens with the
old password first and changes nothing if any file fails. Pass passwords only
as environment variables; never write them to a file.
"""
import base64, json, os, re, sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
b64d, b64e = base64.b64decode, lambda b: base64.b64encode(b).decode()


def kdf(pw, salt, it):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, it).derive(pw.encode())


def main():
    old, new = os.environ.get('OLD_PASSWORD'), os.environ.get('NEW_PASSWORD')
    if not old or not new:
        sys.exit('Set OLD_PASSWORD and NEW_PASSWORD.')
    gp = os.path.join(REPO, 'index.html')
    g = open(gp, encoding='utf-8').read()
    m = re.search(r'const C=(\{.*?\});', g, re.S)
    C = json.loads(m.group(1))
    ko = AESGCM(kdf(old, b64d(C['s']), C['i']))
    try:
        page = ko.decrypt(b64d(C['v']), b64d(C['c']), None)
    except Exception:
        sys.exit('The old password does not unlock the site.')
    files = json.load(open(os.path.join(REPO, 'media.json')))
    for d in ('vid',):
        files += [f'{d}/{f}' for f in os.listdir(os.path.join(REPO, d))]
    if os.path.exists(os.path.join(REPO, 'm', 'names.bin')):
        files.append('m/names.bin')
    files = sorted(set(files))
    plain = {}
    for f in files:
        b = open(os.path.join(REPO, f), 'rb').read()
        try:
            plain[f] = ko.decrypt(b[:12], b[12:], None)
        except Exception:
            sys.exit(f'{f} does not open with the old password; nothing changed.')
    salt = os.urandom(16)
    kn = AESGCM(kdf(new, salt, C['i']))
    iv = os.urandom(12)
    C2 = {'s': b64e(salt), 'v': b64e(iv), 'i': C['i'], 'c': b64e(kn.encrypt(iv, page, None))}
    for f, pt in plain.items():
        iv = os.urandom(12)
        open(os.path.join(REPO, f), 'wb').write(iv + kn.encrypt(iv, pt, None))
    open(gp, 'w', encoding='utf-8').write(g[:m.start(1)] + json.dumps(C2) + g[m.end(1):])
    print(f'Password changed: page + {len(plain)} files re-encrypted.')


if __name__ == '__main__':
    main()
