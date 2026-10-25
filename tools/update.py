#!/usr/bin/env python3
"""Add new messages and photos from a WhatsApp chat export to the Versatiles site.

The site's page (with the chat) is stored encrypted inside index.html, and every
photo is encrypted. This tool needs the site password, passed ONLY as the
VERS_PASSWORD environment variable. Never write the password to a file.

  VERS_PASSWORD=... python3 tools/update.py preview <export.zip|.txt> <scratch-dir>
      Finds messages newer than the site's last one and writes
      <scratch-dir>/pending.json plus photo previews in <scratch-dir>/new-photos/.
      Keep the scratch dir OUTSIDE the repo: it holds real names and chat text.

  (review pending.json: set "drop": true on messages to leave out,
   "drop_photo": true on photos to leave out, edit "x" or "s" as needed)

  VERS_PASSWORD=... python3 tools/update.py apply <scratch-dir>/pending.json
      Adds the kept messages and photos and re-encrypts the page.

Conventions kept from the existing site: senders shown by initials (S.K., V.#2...),
@mentions shown as "@[mention]", other people's names as "[name]", edited
messages end with " (edited)", system notices and deleted-message notices are
left out, each photo is its own message with "p": ["pNNN.jpg"].
"""
import base64, datetime, io, json, os, re, shutil, sys, zipfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NAMES = os.path.join(REPO, 'm', 'names.bin')
b64d, b64e = base64.b64decode, lambda b: base64.b64encode(b).decode()
LRM = '‎‏⁨⁩‪‬﻿'


# ---------------- crypto / site state ----------------
def gate():
    g = open(os.path.join(REPO, 'index.html'), encoding='utf-8').read()
    m = re.search(r'const C=(\{.*?\});', g, re.S)
    return g, m, json.loads(m.group(1))


def get_key():
    pw = os.environ.get('VERS_PASSWORD')
    if not pw:
        sys.exit('Set VERS_PASSWORD (the site password) in the environment.')
    _, _, C = gate()
    key = PBKDF2HMAC(hashes.SHA256(), 32, b64d(C['s']), C['i']).derive(pw.encode())
    try:
        AESGCM(key).decrypt(b64d(C['v']), b64d(C['c']), None)
    except Exception:
        sys.exit('That password does not unlock the site.')
    return key


def enc(key, data):
    iv = os.urandom(12)
    return iv + AESGCM(key).encrypt(iv, data, None)


def dec(key, blob):
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


DRX = re.compile(r'const D=(\[.*?\]);\n', re.S)


def load_page(key):
    _, _, C = gate()
    inner = AESGCM(key).decrypt(b64d(C['v']), b64d(C['c']), None).decode('utf-8')
    D = json.loads(DRX.search(inner).group(1))
    return inner, D


def save_page(key, inner, D):
    js = json.dumps(D, ensure_ascii=False).replace('</', '<\\/')
    inner2 = DRX.sub(lambda m: 'const D=' + js + ';\n', inner, count=1)
    assert json.loads(DRX.search(inner2).group(1).replace('<\\/', '</')) == D
    g, m, C = gate()
    iv = os.urandom(12)
    C2 = {'s': C['s'], 'v': b64e(iv), 'i': C['i'], 'c': b64e(AESGCM(key).encrypt(iv, inner2.encode('utf-8'), None))}
    g2 = g[:m.start(1)] + json.dumps(C2) + g[m.end(1):]
    open(os.path.join(REPO, 'index.html'), 'w', encoding='utf-8').write(g2)


def load_names(key):
    if not os.path.exists(NAMES):
        return {}
    return json.loads(dec(key, open(NAMES, 'rb').read()))


def save_names(key, names):
    os.makedirs(os.path.dirname(NAMES), exist_ok=True)
    open(NAMES, 'wb').write(enc(key, json.dumps(names, ensure_ascii=False, sort_keys=True).encode()))


# ---------------- export parsing ----------------
IOS = re.compile(r'^\[(\d{1,2}/\d{1,2}/\d{2,4}),\s(\d{1,2}:\d{2}(?::\d{2})?)\s?([AaPp]\.?[Mm]\.?)?\]\s(.*?):\s(.*)$')
AND = re.compile(r'^(\d{1,2}/\d{1,2}/\d{2,4}),\s(\d{1,2}:\d{2}(?::\d{2})?)\s?([AaPp]\.?[Mm]\.?)?\s-\s(.*?):\s(.*)$')
ATT_IOS = re.compile(r'<attached:\s*([^>]+)>')
ATT_AND = re.compile(r'^(\S+\.(?:jpe?g|png|webp|mp4|opus|pdf|vcf))\s\(file attached\)', re.I)


def norm(s):
    for c in LRM:
        s = s.replace(c, '')
    return s.replace(' ', ' ').replace(' ', ' ')


def to_dt(d, t, ap, mdy=True):
    a, b, y = d.split('/')
    y = int(y) + (2000 if len(y) == 2 else 0)
    mo, dy = (int(a), int(b)) if mdy else (int(b), int(a))
    parts = [int(x) for x in t.split(':')]
    h, mi, se = parts[0], parts[1], parts[2] if len(parts) > 2 else 0
    if ap:
        ap = ap.lower().replace('.', '')
        h = h % 12 + (12 if ap == 'pm' else 0)
    return datetime.datetime(y, mo, dy, h, mi, se), len(parts) > 2


def read_export(path):
    files = {}
    if zipfile.is_zipfile(path):
        z = zipfile.ZipFile(path)
        txt = next((n for n in z.namelist() if n.lower().endswith('.txt')), None)
        if not txt:
            sys.exit('No chat .txt inside the zip.')
        text = z.read(txt).decode('utf-8-sig', 'replace')
        for n in z.namelist():
            files[os.path.basename(n)] = (z, n)
    else:
        text = open(path, encoding='utf-8-sig', errors='replace').read()
    raw = []
    for orig in text.splitlines():
        line = norm(orig)
        m = IOS.match(line) or AND.match(line)
        if m:
            mark = bool(re.match(r'^‎?\[[^\]]+\][^:]*:\s‎', orig))
            raw.append(list(m.groups()) + [mark])
        elif ANDSYS.match(line) or IOSSYS.match(line):
            raw.append([None] * 6)  # group notice without a sender: its own (skipped) entry
        elif raw:
            raw[-1][4] += '\n' + line
    # day/month order: if any first field > 12 it's d/m/y
    raw = [r for r in raw if r[0]]
    mdy = not any(int(r[0].split('/')[0]) > 12 for r in raw)
    out = []
    for d, t, ap, who, txt, mark in raw:
        dt, secs = to_dt(d, t, ap, mdy)
        out.append({'dt': dt, 'secs': secs, 'name': who.strip(), 'text': txt, 'mark': mark})
    return out, files


def fmt_time(dt):
    return dt.strftime('%I:%M:%S %p').lstrip('0')


def d_dt(m):
    return datetime.datetime.strptime(m['d'] + ' ' + m['t'], '%Y-%m-%d %I:%M:%S %p')


# ---------------- cleaning ----------------
# Android exports: group notices have no "Name:" (skipped by ANDSYS); these are the ones that do
SYSTEM = re.compile(r'^(This message was deleted\.?|You deleted this message\.?|null|<Media omitted>|.* omitted)$', re.I)
ANDSYS = re.compile(r'^\d{1,2}/\d{1,2}/\d{2,4},\s\d{1,2}:\d{2}(?::\d{2})?\s?(?:[AaPp]\.?[Mm]\.?)?\s-\s[^:]*$')
IOSSYS = re.compile(r'^\[\d{1,2}/\d{1,2}/\d{2,4},\s[^\]]+\]\s[^:]*$')
OMIT = re.compile(r'^\s*(image|video|GIF|sticker|audio|document|Contact card|voice message)\s+omitted\s*$', re.I)
EDIT = re.compile(r'\s*<This message was edited>\s*$')
MENTION = re.compile(r'@(?:\+?\d[\d\s]{6,}\d|[^\W\d_][\w.]*(?:\s[A-Z][\w.]*){0,2})')
PHONE = re.compile(r'(?<![\w/=])\+?\d[\d\-\s().]{8,}\d(?![\w/])')
EMAIL = re.compile(r'[\w.+-]+@[\w-]+\.[\w.]+')
FLAG = re.compile(r'\b(wife|husband|son|daughter|kid|kids|children|child|grandson|granddaughter|baby|school|hospital|surgery|cancer|died|passed away|funeral|'
                  r'salary|loan|debt|address|password|passcode)\b|\+?\d[\d\-\s().]{9,}\d|[\w.+-]+@[\w-]+\.[\w.]+', re.I)


def initials(name, taken):
    words = re.findall(r"[^\W\d_]+", name)
    base = ''.join(w[0].upper() + '.' for w in words[:3]) or 'M.'
    if base not in taken:
        return base
    n = 2
    while f'{base}#{n}' in taken:
        n += 1
    return f'{base}#{n}'


def clean_text(txt, names):
    txt = EDIT.sub(' (edited)', txt) if EDIT.search(txt) else txt
    txt = EMAIL.sub('[email]', txt)
    txt = MENTION.sub('@[mention]', txt)
    txt = PHONE.sub(lambda m: '[number]' if len(re.sub(r'\D', '', m.group(0))) >= 10 else m.group(0), txt)
    # members' real names (full and first names) -> their initials, longest first
    pairs = []
    for real, ini in names.items():
        if re.search(r'\d{6,}', real):
            continue
        pairs.append((real, ini))
        first = real.split()[0]
        if len(first) >= 3:
            pairs.append((first, ini))
    for real, ini in sorted(pairs, key=lambda p: -len(p[0])):
        txt = re.sub(r'(?<!\w)' + re.escape(real) + r'(?!\w)', ini, txt, flags=re.I)
    return txt.strip()


# ---------------- preview ----------------
def preview(export, scratch):
    key = get_key()
    inner, D = load_page(key)
    names = load_names(key)
    msgs, files = read_export(export)
    if not msgs:
        sys.exit('No messages found in the export.')
    last = d_dt(D[-1])

    # learn real-name -> initials from messages already on the site
    idx = {}
    for m in D:
        idx.setdefault((m['d'], m['t']), []).append(m)
        idx.setdefault((m['d'], m['t'][:-6] + m['t'][-3:]), []).append(m)  # minute-precision key
    learned = 0
    for e in msgs:
        if e['dt'] > last or e['name'] in names:
            continue
        k = (e['dt'].strftime('%Y-%m-%d'), fmt_time(e['dt']) if e['secs'] else e['dt'].strftime('%I:%M %p').lstrip('0'))
        cands = {m['s'] for m in idx.get(k, [])}
        if len(cands) == 1:
            names[e['name']] = cands.pop()
            learned += 1

    taken = set(names.values()) | {m['s'] for m in D}
    seen = {(m['d'], m['t'], m['x']) for m in D}
    new_names, out = {}, []
    os.makedirs(scratch, exist_ok=True)
    pdir = os.path.join(scratch, 'new-photos')
    shutil.rmtree(pdir, ignore_errors=True)
    os.makedirs(pdir)
    def skip(e):
        # iPhone exports mark notices, deleted messages and omitted media with an invisible mark
        return (e['mark'] and not ATT_IOS.search(e['text'])) or bool(SYSTEM.match(e['text'].strip()))
    for e in msgs:  # name every new sender first, so their names are replaced in all messages
        who = e['name']
        if e['dt'] <= last or skip(e) or who in names or who in new_names:
            continue
        held = set(names.values()) | set(new_names.values())
        base = initials(who, set())
        # an initial already on the site that no known person holds is probably this person
        new_names[who] = base if (base in taken and base not in held) else initials(who, taken)
        taken.add(new_names[who])
    for e in msgs:
        if e['dt'] <= last or skip(e):
            continue
        txt = e['text']
        who = e['name']
        s = names.get(who) or new_names[who]
        att = ATT_IOS.search(txt)
        fname = att.group(1).strip() if att else (ATT_AND.match(txt).group(1) if ATT_AND.match(txt) else None)
        if att:
            txt = ATT_IOS.sub('', txt)
        elif fname:
            txt = ATT_AND.sub('', txt)
        if OMIT.match(txt):
            txt = ''
        photo = None
        if fname and re.search(r'\.(jpe?g|png)$', fname, re.I) and fname in files:
            z, n = files[fname]
            photo = os.path.join(pdir, fname)
            open(photo, 'wb').write(z.read(n))
        elif fname or (not txt.strip() and OMIT.match(e['text'] or '')):
            if not txt.strip():
                continue  # video, voice note, sticker, document: not added to the site
        x = clean_text(txt, {**names, **new_names})
        if not x and not photo:
            continue
        rec = {'d': e['dt'].strftime('%Y-%m-%d'), 't': fmt_time(e['dt']), 'name': who, 's': s, 'x': x, 'drop': False}
        if (rec['d'], rec['t'], rec['x']) in seen:
            continue
        fl = sorted({m.group(0).lower() for m in FLAG.finditer(x)})
        if fl:
            rec['flags'] = fl
        if photo:
            rec['photo'] = os.path.basename(photo)
            rec['drop_photo'] = False
        out.append(rec)
    pending = {'last_on_site': D[-1]['d'] + ' ' + D[-1]['t'], 'site_messages': len(D),
               'names_learned_from_site': learned, 'new_names': new_names, 'messages': out}
    pj = os.path.join(scratch, 'pending.json')
    json.dump(pending, open(pj, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    # keep the learned map so later runs don't need the overlap
    save_names(key, names)
    print(f'{len(out)} new messages ({sum(1 for r in out if "photo" in r)} with photos, '
          f'{sum(1 for r in out if r.get("flags"))} flagged) after {pending["last_on_site"]}.')
    print(f'Names known: {len(names)} ({learned} learned now); new senders: {new_names or "none"}')
    print('Review:', pj)


# ---------------- apply ----------------
def next_photo_number():
    nums = [int(m.group(1)) for f in os.listdir(os.path.join(REPO, 'photos')) for m in [re.match(r'p(\d+)\.jpg$', f)] if m]
    return max(nums, default=0) + 1


def shrink(path):
    from PIL import Image, ImageOps
    im = ImageOps.exif_transpose(Image.open(path)).convert('RGB')  # also drops EXIF (GPS etc.)
    im.thumbnail((1280, 1280))
    buf = io.BytesIO()
    im.save(buf, 'JPEG', quality=80, optimize=True, progressive=True)
    return buf.getvalue()


def apply(pending_path):
    key = get_key()
    inner, D = load_page(key)
    pend = json.load(open(pending_path, encoding='utf-8'))
    if D[-1]['d'] + ' ' + D[-1]['t'] != pend['last_on_site'] or len(D) != pend['site_messages']:
        sys.exit('The site changed since this preview. Run preview again.')
    names = load_names(key)
    for real, ini in pend.get('new_names', {}).items():
        names[real] = ini
    pdir = os.path.join(os.path.dirname(os.path.abspath(pending_path)), 'new-photos')
    media = json.load(open(os.path.join(REPO, 'media.json')))
    n = next_photo_number()
    added = photos = 0
    for r in pend['messages']:
        if r.get('drop'):
            continue
        m = {'d': r['d'], 't': r['t'], 's': r['s'], 'x': r.get('x', '')}
        if r.get('photo') and not r.get('drop_photo'):
            fn = f'p{n:03d}.jpg'
            n += 1
            open(os.path.join(REPO, 'photos', fn), 'wb').write(enc(key, shrink(os.path.join(pdir, r['photo']))))
            media.append('photos/' + fn)
            m['p'] = [fn]
            photos += 1
        elif not m['x']:
            continue
        D.append(m)
        added += 1
    save_page(key, inner, D)
    json.dump(media, open(os.path.join(REPO, 'media.json'), 'w'))
    save_names(key, names)
    print(f'Added {added} messages ({photos} photos). Site now has {len(D)} messages.')


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'preview':
        preview(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == 'apply':
        apply(sys.argv[2])
    else:
        sys.exit(__doc__)
