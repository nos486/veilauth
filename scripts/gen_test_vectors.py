#!/usr/bin/env python3
"""Independent reference implementation of spec/crypto.md that emits spec/test-vectors.json.

This deliberately shares no code with packages/crypto or packages/otp: it uses Python's
`cryptography` package (OpenSSL) for every primitive, so the TypeScript and Kotlin
implementations are checked against a second, unrelated implementation.

Usage:
  python3 -I scripts/gen_test_vectors.py          # (re)write spec/test-vectors.json
  python3 -I scripts/gen_test_vectors.py --check  # fail if the file is out of date
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import sys
import unicodedata
from pathlib import Path
from urllib.parse import quote, unquote

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "spec" / "test-vectors.json"
WORDLIST = ROOT / "spec" / "bip39-english.txt"
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

ENVELOPE_VERSION = 1
KDF_V1 = {"m": 65536, "t": 3, "p": 1}
PBKDF2_ITERATIONS = 100_000


# ---------------------------------------------------------------- encoding helpers

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b32(b: bytes) -> str:
    return base64.b32encode(b).decode().rstrip("=")


def h(b: bytes) -> str:
    return b.hex()


def jcs(obj: object) -> bytes:
    """RFC 8785 for the restricted type set in spec/crypto.md §6.1."""
    def check(o: object) -> None:
        if isinstance(o, float):
            raise ValueError("floats are forbidden")
        if isinstance(o, dict):
            for v in o.values():
                check(v)
        if isinstance(o, list):
            for v in o:
                check(v)
    check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def pad(data: bytes) -> bytes:
    body = struct.pack(">I", len(data)) + data
    return body + b"\x00" * (-len(body) % 256)


# ---------------------------------------------------------------- crypto per spec

def norm_password(pw: str) -> bytes:
    return unicodedata.normalize("NFKC", pw).encode("utf-8")


def norm_email(e: str) -> str:
    return unicodedata.normalize("NFKC", e.strip()).lower()


def argon2id(pw: bytes, salt: bytes, m: int, t: int, p: int, length: int = 32) -> bytes:
    return Argon2id(salt=salt, length=length, iterations=t, lanes=p, memory_cost=m).derive(pw)


def hkdf(ikm: bytes, info: str, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info.encode()).derive(ikm)


def pbkdf2(secret: bytes, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations).derive(secret)


def seal(key: bytes, pt: bytes, ctx: str, nonce: bytes, version: int = ENVELOPE_VERSION) -> str:
    assert len(key) == 32 and len(nonce) == 12
    aad = bytes([version]) + ctx.encode("ascii")
    return b64u(bytes([version]) + nonce + AESGCM(key).encrypt(nonce, pt, aad))


def open_(key: bytes, env: str, ctx: str) -> bytes:
    raw = b64u_dec(env)
    assert raw[0] == ENVELOPE_VERSION
    return AESGCM(key).decrypt(raw[1:13], raw[13:], raw[:1] + ctx.encode("ascii"))


def ctx_vk(uid: str) -> str:
    return f"zk2fa/v1/vk|{uid}"


def ctx_rvk(uid: str) -> str:
    return f"zk2fa/v1/rvk|{uid}"


def ctx_item(uid: str, iid: str, kind: str) -> str:
    return f"zk2fa/v1/item|{uid}|{iid}|{kind}"


def ctx_backup(salt: bytes) -> str:
    return f"zk2fa/v1/backup|{b64u(salt)}"


def bip39_encode(entropy: bytes, words: list[str]) -> str:
    assert len(entropy) == 32
    bits = int.from_bytes(entropy, "big") << 8 | hashlib.sha256(entropy).digest()[0]
    idx = [(bits >> (11 * (23 - i))) & 0x7FF for i in range(24)]
    return " ".join(words[i] for i in idx)


def bip39_decode(mnemonic: str, words: list[str]) -> bytes:
    idx = [words.index(w) for w in mnemonic.split()]
    assert len(idx) == 24
    bits = 0
    for i in idx:
        bits = bits << 11 | i
    entropy = (bits >> 8).to_bytes(32, "big")
    assert hashlib.sha256(entropy).digest()[0] == bits & 0xFF
    return entropy


# ---------------------------------------------------------------- OTP per RFC 4226 / 6238

def hotp(secret: bytes, counter: int, digits: int = 6, alg: str = "SHA1") -> str:
    mac = hmac.new(secret, struct.pack(">Q", counter), alg.lower()).digest()
    o = mac[-1] & 0x0F
    code = int.from_bytes(mac[o:o + 4], "big") & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)


def totp(secret: bytes, t_sec: int, period: int = 30, digits: int = 6, alg: str = "SHA1") -> str:
    return hotp(secret, t_sec // period, digits, alg)


STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"


def steam(secret: bytes, t_sec: int) -> str:
    mac = hmac.new(secret, struct.pack(">Q", t_sec // 30), "sha1").digest()
    o = mac[-1] & 0x0F
    code = int.from_bytes(mac[o:o + 4], "big") & 0x7FFFFFFF
    out = []
    for _ in range(5):
        out.append(STEAM_ALPHABET[code % 26])
        code //= 26
    return "".join(out)


# ---------------------------------------------------------------- protobuf encoder (migration)

def pb_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def pb_field(num: int, value: int | bytes | str) -> bytes:
    if isinstance(value, int):
        return pb_varint(num << 3 | 0) + pb_varint(value)
    if isinstance(value, str):
        value = value.encode("utf-8")
    return pb_varint(num << 3 | 2) + pb_varint(len(value)) + value


def pb_otp(secret: bytes, name: str, issuer: str, alg: int, digits: int, typ: int, counter: int = 0) -> bytes:
    msg = pb_field(1, secret) + pb_field(2, name)
    if issuer:
        msg += pb_field(3, issuer)
    if alg:
        msg += pb_field(4, alg)
    if digits:
        msg += pb_field(5, digits)
    if typ:
        msg += pb_field(6, typ)
    if counter:
        msg += pb_field(7, counter)
    return msg


def migration_uri(otps: list[bytes], size: int, index: int, batch_id: int) -> str:
    payload = b"".join(pb_field(1, o) for o in otps)
    payload += pb_field(2, 1) + pb_field(3, size) + pb_field(4, index) + pb_field(5, batch_id)
    return "otpauth-migration://offline?data=" + quote(base64.b64encode(payload).decode(), safe="")


# ---------------------------------------------------------------- vectors

def seq(start: int, n: int) -> bytes:
    return bytes((start + i) & 0xFF for i in range(n))


USER_ID = "0192d5f0-6a3c-7c1e-8b2a-3f4e5d6c7b8a"
USER_ID_2 = "0192d5f0-6a3c-7c1e-9b2a-000000000002"
ITEM_IDS = [
    "0192d5f1-0000-7000-8000-000000000001",
    "0192d5f1-0000-7000-8000-000000000002",
    "0192d5f1-0000-7000-8000-000000000003",
    "0192d5f1-0000-7000-8000-000000000004",
    "0192d5f1-0000-7000-8000-000000000005",
    "0192d5f1-0000-7000-8000-000000000006",
]
VAULT_KEY = seq(0xA0, 32)


def token(**over: object) -> dict:
    base = {
        "type": "totp", "issuer": "", "account": "", "secret": "", "algorithm": "SHA1",
        "digits": 6, "period": 30, "counter": 0, "iconId": None, "folderId": None, "tags": [],
        "notes": "", "favorite": False, "createdAt": 1760000000000, "trashedAt": None,
    }
    base.update(over)
    return base


def gen_key_hierarchy() -> list[dict]:
    cases = [
        ("ascii", "alice@example.com", "correct horse battery staple", seq(0x10, 16), seq(0x20, 16), seq(0x30, 32), seq(0x40, 12)),
        ("nfkc", "bob@example.com", "Ｐässwörd ﬁ Ⅻ", seq(0x50, 16), seq(0x60, 16), seq(0x70, 32), seq(0x80, 12)),
    ]
    out = []
    for name, email, pw, salt, auth_salt, vk, nonce in cases:
        npw = norm_password(pw)
        mk = argon2id(npw, salt, **KDF_V1)
        auth, kek = hkdf(mk, "zk2fa/v1/auth"), hkdf(mk, "zk2fa/v1/kek")
        wrapped = seal(kek, vk, ctx_vk(USER_ID), nonce)
        assert open_(kek, wrapped, ctx_vk(USER_ID)) == vk
        out.append({
            "name": name, "email": email, "password": pw, "normalizedPasswordHex": h(npw),
            "kdf": {"alg": "argon2id", "version": 1, "params": KDF_V1, "saltB64": b64u(salt)},
            "userId": USER_ID,
            "masterKeyHex": h(mk), "authKeyHex": h(auth), "kekHex": h(kek),
            "authKeyB64": b64u(auth),
            "authSaltB64": b64u(auth_salt), "authHashB64": b64u(pbkdf2(auth, auth_salt)),
            "vaultKeyHex": h(vk), "wrapNonceHex": h(nonce), "wrappedVaultKey": wrapped,
        })
    return out


def gen_recovery(words: list[str]) -> list[dict]:
    out = []
    for name, entropy, auth_salt, nonce in [
        ("sequential", seq(0x00, 32), seq(0x90, 16), seq(0xB0, 12)),
        ("all-ff", b"\xff" * 32, seq(0x91, 16), seq(0xC0, 12)),
    ]:
        mnemonic = bip39_encode(entropy, words)
        assert bip39_decode(mnemonic, words) == entropy
        rkek, rauth = hkdf(entropy, "zk2fa/v1/recovery-kek"), hkdf(entropy, "zk2fa/v1/recovery-auth")
        out.append({
            "name": name, "recoveryKeyHex": h(entropy), "mnemonic": mnemonic,
            "recoveryKekHex": h(rkek), "recoveryAuthHex": h(rauth),
            "recoveryAuthSaltB64": b64u(auth_salt), "recoveryAuthHashB64": b64u(pbkdf2(rauth, auth_salt)),
            "userId": USER_ID, "vaultKeyHex": h(VAULT_KEY), "wrapNonceHex": h(nonce),
            "recoveryWrappedVaultKey": seal(rkek, VAULT_KEY, ctx_rvk(USER_ID), nonce),
        })
    # BIP39 reference vector (trezor/python-mnemonic vectors.json, 256-bit 0x7f..)
    assert bip39_encode(b"\x7f" * 32, words) == (
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage "
        "worth useful legal winner thank year wave sausage worth title")
    return out


def gen_items() -> list[dict]:
    defs = [
        ("totp-basic", ITEM_IDS[0], "token", token(
            issuer="GitHub", account="alice@example.com", secret="JBSWY3DPEHPK3PXP",
            iconId="github", tags=["work"], favorite=True)),
        ("hotp-unicode-escapes", ITEM_IDS[1], "token", token(
            type="hotp", issuer="Bänk 銀行", account="bob", secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            algorithm="SHA512", digits=8, counter=42, folderId=ITEM_IDS[3],
            notes="line1\nline2\t\"quoted\" back\\slash \u0001 🔐  ", tags=["bank", "ünï"])),
        ("steam", ITEM_IDS[2], "token", token(
            type="steam", issuer="Steam", account="gaben", secret="GEZDGNBVGY3TQOJQ", digits=5,
            iconId="steam", trashedAt=1760000500000)),
        ("folder", ITEM_IDS[3], "folder", {"name": "Work 💼", "createdAt": 1760000000000}),
        ("settings", ITEM_IDS[4], "settings", {
            "autoLockSeconds": 60, "hideCodes": False, "order": ITEM_IDS[:3], "theme": "system"}),
        ("two-buckets", ITEM_IDS[5], "token", token(
            issuer="LongNotes", account="carol", secret="MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOV3HO6DZPI",
            algorithm="SHA256", digits=7, period=60, notes="x" * 300)),
    ]
    out = []
    for i, (name, iid, kind, obj) in enumerate(defs):
        cj = jcs(obj)
        padded = pad(cj)
        nonce = seq(0x01 + i * 16, 12)
        ctx = ctx_item(USER_ID, iid, kind)
        env = seal(VAULT_KEY, padded, ctx, nonce)
        assert open_(VAULT_KEY, env, ctx) == padded
        out.append({
            "name": name, "userId": USER_ID, "itemId": iid, "kind": kind, "plaintext": obj,
            "aad": ctx, "canonicalJson": cj.decode("utf-8"), "paddedLength": len(padded),
            "paddedHex": h(padded), "nonceHex": h(nonce), "envelope": env,
        })
    return out


def gen_tamper(items: list[dict]) -> list[dict]:
    base = items[0]
    raw = b64u_dec(base["envelope"])

    def flip(i: int) -> str:
        b = bytearray(raw)
        b[i] ^= 0x01
        return b64u(bytes(b))

    def case(name: str, env: str, key: bytes = VAULT_KEY, user: str = USER_ID,
             item: str = base["itemId"], kind: str = base["kind"]) -> dict:
        return {"name": name, "keyHex": h(key), "userId": user, "itemId": item, "kind": kind,
                "envelope": env, "error": "DECRYPT_FAILED"}

    other_key = bytes(b ^ 0x5A for b in VAULT_KEY)
    bad_padding_nonzero = seal(VAULT_KEY, pad(b"{}")[:-1] + b"\x01", base["aad"], seq(0xE0, 12))
    bad_padding_len = seal(VAULT_KEY, struct.pack(">I", 9999) + b"{}" + b"\x00" * 250, base["aad"], seq(0xE1, 12))
    bad_padding_bucket = seal(VAULT_KEY, struct.pack(">I", 2) + b"{}" + b"\x00" * 10, base["aad"], seq(0xE2, 12))
    return [
        case("flipped-ciphertext-bit", flip(13)),
        case("flipped-tag-bit", flip(len(raw) - 1)),
        case("flipped-nonce-bit", flip(1)),
        case("truncated-tag", b64u(raw[:-1])),
        case("wrong-item-id", base["envelope"], item=ITEM_IDS[1]),
        case("wrong-user-id", base["envelope"], user=USER_ID_2),
        case("wrong-kind", base["envelope"], kind="folder"),
        case("wrong-key", base["envelope"], key=other_key),
        case("swapped-blob-from-other-item", items[1]["envelope"]),
        case("padding-nonzero-byte", bad_padding_nonzero),
        case("padding-length-overflow", bad_padding_len),
        case("padding-not-bucket-multiple", bad_padding_bucket),
    ]


def gen_invalid_envelopes(items: list[dict]) -> list[dict]:
    raw = b64u_dec(items[0]["envelope"])
    v2 = seal(VAULT_KEY, b"x", items[0]["aad"], seq(0xF0, 12), version=2)
    return [
        {"name": "base64-padding", "envelope": items[0]["envelope"] + "=", "error": "INVALID_ENVELOPE"},
        {"name": "standard-base64-alphabet", "envelope": base64.b64encode(raw).decode(), "error": "INVALID_ENVELOPE"},
        {"name": "whitespace", "envelope": items[0]["envelope"][:10] + " " + items[0]["envelope"][10:], "error": "INVALID_ENVELOPE"},
        {"name": "too-short", "envelope": b64u(raw[:28]), "error": "INVALID_ENVELOPE"},
        {"name": "empty", "envelope": "", "error": "INVALID_ENVELOPE"},
        {"name": "version-0", "envelope": b64u(b"\x00" + raw[1:]), "error": "INVALID_ENVELOPE"},
        {"name": "version-2", "envelope": v2, "error": "INVALID_ENVELOPE"},
        {"name": "non-canonical-trailing-bits", "envelope": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB", "error": "INVALID_ENVELOPE"},
    ]


def backup_file(password: str, contents: dict, salt: bytes, nonce: bytes) -> tuple[str, dict]:
    key = hkdf(argon2id(norm_password(password), salt, **KDF_V1), "zk2fa/v1/backup")
    padded = pad(jcs(contents))
    data = seal(key, padded, ctx_backup(salt), nonce)
    assert open_(key, data, ctx_backup(salt)) == padded
    file = {"format": "veilauth-backup", "version": 1,
            "kdf": {"alg": "argon2id", "params": KDF_V1, "salt": b64u(salt)}, "data": data}
    return jcs(file).decode("utf-8"), {"backupKeyHex": h(key), "paddedLength": len(padded)}


def gen_backup(items: list[dict]) -> dict:
    tokens = [i["plaintext"] for i in items if i["kind"] == "token"]
    cases = []
    for name, pw, contents, salt, nonce in [
        ("three-tokens", "backup password 1", {"exportedAt": 1760001000000, "tokens": tokens}, seq(0xC1, 16), seq(0xD1, 12)),
        ("empty-nfkc-password", "Ｐässwörd ﬁ", {"exportedAt": 0, "tokens": []}, seq(0xC2, 16), seq(0xD2, 12)),
    ]:
        file, extra = backup_file(pw, contents, salt, nonce)
        cases.append({"name": name, "password": pw, "saltHex": h(salt), "nonceHex": h(nonce),
                      "contents": contents, "aad": ctx_backup(salt), **extra, "file": file})
    base = json.loads(cases[1]["file"])
    pw = cases[1]["password"]

    def variant(**over: object) -> str:
        f = dict(base)
        f.update(over)
        return jcs(f).decode("utf-8")

    other_salt = b64u(seq(0xC3, 16))
    weak = {"alg": "argon2id", "params": {"m": 32768, "t": 3, "p": 1}, "salt": base["kdf"]["salt"]}
    not_object, _ = backup_file(pw, {"exportedAt": 0, "tokens": {}}, seq(0xC4, 16), seq(0xD4, 12))
    rejected = [
        {"name": "wrong-password", "password": pw + "!", "file": cases[1]["file"], "error": "DECRYPT_FAILED"},
        {"name": "salt-swapped", "password": pw, "file": variant(kdf={**base["kdf"], "salt": other_salt}), "error": "DECRYPT_FAILED"},
        {"name": "not-json", "password": pw, "file": "veilauth", "error": "INVALID_BACKUP"},
        {"name": "wrong-format", "password": pw, "file": variant(format="other"), "error": "INVALID_BACKUP"},
        {"name": "version-2", "password": pw, "file": variant(version=2), "error": "INVALID_BACKUP"},
        {"name": "data-not-envelope", "password": pw, "file": variant(data="AA"), "error": "INVALID_BACKUP"},
        {"name": "weak-kdf", "password": pw, "file": variant(kdf=weak), "error": "KDF_PARAMS_REJECTED"},
        {"name": "tokens-not-array", "password": pw, "file": not_object, "error": "INVALID_BACKUP"},
    ]
    return {"cases": cases, "rejected": rejected}


def gen_padding() -> list[dict]:
    out = []
    for name, obj in [("empty-object", {}), ("ascii", {"b": 1, "a": "x"}),
                      ("exact-252", {"k": "y" * 244}), ("exact-253", {"k": "y" * 245})]:
        cj = jcs(obj)
        p = pad(cj)
        out.append({"name": name, "value": obj, "canonicalJson": cj.decode(), "jsonLength": len(cj),
                    "paddedLength": len(p), "paddedHex": h(p)})
    assert out[2]["paddedLength"] == 256 and out[3]["paddedLength"] == 512
    return out


def gen_fake_salt() -> dict:
    secret = seq(0xC8, 32)
    emails = ["alice@example.com", "  Alice@Example.COM ", "ＡＬＩＣＥ@example.com", "nobody@nowhere.test"]
    cases = []
    for e in emails:
        n = norm_email(e)
        cases.append({"email": e, "normalized": n,
                      "saltB64": b64u(hmac.new(secret, n.encode(), "sha256").digest()[:16])})
    assert cases[0]["saltB64"] == cases[1]["saltB64"] == cases[2]["saltB64"]
    return {"secretB64": b64u(secret), "kdf": {"alg": "argon2id", "version": 1, "params": KDF_V1}, "cases": cases}


def gen_hkdf() -> list[dict]:
    out = []
    for ikm, info in [(seq(0x00, 32), "zk2fa/v1/auth"), (seq(0x00, 32), "zk2fa/v1/kek"),
                      (seq(0x00, 32), "zk2fa/v1/recovery-kek"), (seq(0x00, 32), "zk2fa/v1/recovery-auth")]:
        out.append({"ikmHex": h(ikm), "info": info, "okmHex": h(hkdf(ikm, info))})
    # RFC 5869 test case 3 (empty salt, empty info) to pin the empty-salt semantics.
    tc3 = HKDF(algorithm=hashes.SHA256(), length=42, salt=None, info=b"").derive(bytes([0x0B] * 22))
    assert tc3.hex() == ("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                         "9d201395faa4b61a96c8")
    out.append({"ikmHex": "0b" * 22, "info": "", "length": 42, "okmHex": h(tc3), "note": "RFC 5869 A.3"})
    return out


def gen_kdf_rejected() -> list[dict]:
    salt = b64u(seq(0x10, 16))
    return [
        {"name": "memory-too-low", "alg": "argon2id", "params": {"m": 32768, "t": 3, "p": 1}, "saltB64": salt},
        {"name": "memory-too-high", "alg": "argon2id", "params": {"m": 1048576, "t": 3, "p": 1}, "saltB64": salt},
        {"name": "passes-too-low", "alg": "argon2id", "params": {"m": 65536, "t": 2, "p": 1}, "saltB64": salt},
        {"name": "passes-too-high", "alg": "argon2id", "params": {"m": 65536, "t": 17, "p": 1}, "saltB64": salt},
        {"name": "parallelism-not-1", "alg": "argon2id", "params": {"m": 65536, "t": 3, "p": 4}, "saltB64": salt},
        {"name": "wrong-alg", "alg": "argon2i", "params": {"m": 65536, "t": 3, "p": 1}, "saltB64": salt},
        {"name": "pbkdf2-downgrade", "alg": "pbkdf2", "params": {"m": 65536, "t": 3, "p": 1}, "saltB64": salt},
        {"name": "short-salt", "alg": "argon2id", "params": {"m": 65536, "t": 3, "p": 1}, "saltB64": b64u(seq(0x10, 15))},
        {"name": "long-salt", "alg": "argon2id", "params": {"m": 65536, "t": 3, "p": 1}, "saltB64": b64u(seq(0x10, 32))},
        {"name": "fractional-memory", "alg": "argon2id", "params": {"m": 65536.5, "t": 3, "p": 1}, "saltB64": salt},
    ]


def gen_otp() -> dict:
    rfc_secret = {"SHA1": b"12345678901234567890", "SHA256": b"12345678901234567890" + b"123456789012",
                  "SHA512": b"1234567890" * 6 + b"1234"}
    rfc4226 = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
    hotp_v = []
    for c, exp in enumerate(rfc4226):
        got = hotp(rfc_secret["SHA1"], c)
        assert got == exp
        hotp_v.append({"secretHex": h(rfc_secret["SHA1"]), "counter": c, "digits": 6, "algorithm": "SHA1", "code": got})
    hotp_v.append({"secretHex": h(rfc_secret["SHA512"]), "counter": 2**40 + 7, "digits": 7, "algorithm": "SHA512",
                   "code": hotp(rfc_secret["SHA512"], 2**40 + 7, 7, "SHA512")})
    rfc6238 = {
        59: ("94287082", "46119246", "90693936"),
        1111111109: ("07081804", "68084774", "25091201"),
        1111111111: ("14050471", "67062674", "99943326"),
        1234567890: ("89005924", "91819424", "93441116"),
        2000000000: ("69279037", "90698825", "38618901"),
        20000000000: ("65353130", "77737706", "47863826"),
    }
    totp_v = []
    for t, codes in rfc6238.items():
        for alg, exp in zip(("SHA1", "SHA256", "SHA512"), codes):
            got = totp(rfc_secret[alg], t, 30, 8, alg)
            assert got == exp, (t, alg)
            totp_v.append({"secretHex": h(rfc_secret[alg]), "timeMs": t * 1000, "period": 30, "digits": 8,
                           "algorithm": alg, "code": got})
    gsec = base64.b32decode("JBSWY3DPEHPK3PXP")
    for t, period, digits in [(1760000000, 30, 6), (1760000029, 30, 6), (1760000030, 30, 6),
                              (1760000000, 60, 7), (1760000000, 15, 6)]:
        totp_v.append({"secretHex": h(gsec), "timeMs": t * 1000 + 999, "period": period, "digits": digits,
                       "algorithm": "SHA1", "code": totp(gsec, t, period, digits)})
    steam_v = []
    for sec_b32, t in [("GEZDGNBVGY3TQOJQ", 1760000000), ("GEZDGNBVGY3TQOJQ", 1760000030),
                       ("JBSWY3DPEHPK3PXP", 0), ("JBSWY3DPEHPK3PXP", 1234567890),
                       ("MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOV3HO6DZPI", 2000000000)]:
        steam_v.append({"secretB32": sec_b32, "timeMs": t * 1000, "code": steam(base64.b32decode(sec_b32 + "=" * (-len(sec_b32) % 8)), t)})
    return {"hotp": hotp_v, "totp": totp_v, "steam": steam_v,
            "otpauth": gen_otpauth_cases(), "migration": gen_migration_cases()}


def parsed(type_: str, issuer: str, account: str, secret: str, algorithm: str = "SHA1",
           digits: int = 6, period: int = 30, counter: int = 0) -> dict:
    return {"type": type_, "issuer": issuer, "account": account, "secret": secret, "algorithm": algorithm,
            "digits": digits, "period": period, "counter": counter}


def gen_otpauth_cases() -> list[dict]:
    S = "JBSWY3DPEHPK3PXP"
    ok = [
        ("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
         parsed("totp", "Example", "alice@google.com", S)),
        ("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
         parsed("totp", "ACME Co", "john.doe@email.com", "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", "SHA256", 8, 60)),
        ("otpauth://totp/x?secret=jbsw%20y3dp%20ehpk%203pxp", parsed("totp", "", "x", S)),
        ("otpauth://totp/x?secret=MFRGG%3D%3D%3D", parsed("totp", "", "x", "MFRGG")),
        ("otpauth://hotp/Bank:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=42&issuer=Bank&algorithm=SHA512&digits=7",
         parsed("hotp", "Bank", "bob", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA512", 7, 30, 42)),
        ("otpauth://hotp/Bank:bob?secret=JBSWY3DPEHPK3PXP&counter=0&period=90", parsed("hotp", "Bank", "bob", S)),
        ("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub", parsed("totp", "GitHub", "alice", S)),
        ("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP", parsed("totp", "GitHub", "alice", S)),
        ("otpauth://totp/Old%20Name:alice?secret=JBSWY3DPEHPK3PXP&issuer=New%20Name", parsed("totp", "New Name", "alice", S)),
        ("otpauth://totp/Big%20Corp%3A%20alice?secret=JBSWY3DPEHPK3PXP", parsed("totp", "Big Corp", "alice", S)),
        ("otpauth://totp/a:b:c?secret=JBSWY3DPEHPK3PXP", parsed("totp", "a", "b:c", S)),
        ("otpauth://totp/?secret=JBSWY3DPEHPK3PXP&issuer=OnlyIssuer", parsed("totp", "OnlyIssuer", "", S)),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=sha512&digits=8", parsed("totp", "", "x", S, "SHA512", 8)),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA-256", parsed("totp", "", "x", S, "SHA256")),
        ("OTPAUTH://TOTP/Example:alice?secret=JBSWY3DPEHPK3PXP", parsed("totp", "Example", "alice", S)),
        ("  otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP\n", parsed("totp", "Example", "alice", S)),
        ("otpauth://totp/%E5%BE%AE%E8%BD%AF:%E7%94%A8%E6%88%B7?secret=JBSWY3DPEHPK3PXP", parsed("totp", "微软", "用户", S)),
        ("otpauth://totp/Steam:gaben?secret=GEZDGNBVGY3TQOJQ&issuer=Steam", parsed("steam", "Steam", "gaben", "GEZDGNBVGY3TQOJQ", "SHA1", 5)),
        ("otpauth://totp/steam:gaben?secret=GEZDGNBVGY3TQOJQ&digits=6", parsed("steam", "steam", "gaben", "GEZDGNBVGY3TQOJQ", "SHA1", 5)),
        ("otpauth://steam/Steam:gaben?secret=GEZDGNBVGY3TQOJQ", parsed("steam", "Steam", "gaben", "GEZDGNBVGY3TQOJQ", "SHA1", 5)),
        ("otpauth://totp/MySteam:gaben?secret=GEZDGNBVGY3TQOJQ&encoder=steam", parsed("steam", "MySteam", "gaben", "GEZDGNBVGY3TQOJQ", "SHA1", 5)),
        ("steam://GEZDGNBVGY3TQOJQ", parsed("steam", "Steam", "", "GEZDGNBVGY3TQOJQ", "SHA1", 5)),
    ]
    bad = [
        ("otpauth://totp/x?issuer=a", "MISSING_SECRET"),
        ("otpauth://totp/x?secret=", "MISSING_SECRET"),
        ("otpauth://totp/x?secret=JBSW1", "INVALID_SECRET"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PX", "INVALID_SECRET"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", "INVALID_ALGORITHM"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=10", "INVALID_DIGITS"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6abc", "INVALID_DIGITS"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0", "INVALID_PERIOD"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=86401", "INVALID_PERIOD"),
        ("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP", "INVALID_COUNTER"),
        ("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=-1", "INVALID_COUNTER"),
        ("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=9007199254740992", "INVALID_COUNTER"),
        ("http://example.com/?secret=JBSWY3DPEHPK3PXP", "INVALID_URI"),
        ("not a uri", "INVALID_URI"),
        ("otpauth://foo/x?secret=JBSWY3DPEHPK3PXP", "UNSUPPORTED_TYPE"),
        ("otpauth://totp/%E0%A4%A?secret=JBSWY3DPEHPK3PXP", "INVALID_URI"),
    ]
    return [{"uri": u, "expected": e} for u, e in ok] + [{"uri": u, "error": e} for u, e in bad]


def gen_migration_cases() -> list[dict]:
    s1, s2, s3 = b"Hello!\xde\xad\xbe\xef", seq(0x00, 20), seq(0x41, 10)
    single = migration_uri([
        pb_otp(s1, "Example:alice", "Example", 1, 1, 2),
        pb_otp(s2, "bob", "", 2, 2, 1, counter=5),
        pb_otp(s3, "GitHub:carol", "GitHub", 0, 0, 0),
        pb_otp(s3, "Legacy:md5", "Legacy", 4, 1, 2),
        pb_otp(s1, "Other:dave", "Example", 3, 2, 2),
    ], 1, 0, 123456)
    single_bytes = base64.b64decode(unquote(single.split("data=")[1]))
    truncated = "otpauth-migration://offline?data=" + quote(base64.b64encode(single_bytes[:40]).decode(), safe="")
    batch = [
        migration_uri([pb_otp(s1, "A:one", "A", 1, 1, 2)], 2, 0, -5 & 0xFFFFFFFFFFFFFFFF),
        migration_uri([pb_otp(s2, "B:two", "B", 1, 1, 2)], 2, 1, -5 & 0xFFFFFFFFFFFFFFFF),
    ]
    ok = lambda p: {"ok": True, "value": p}  # noqa: E731
    return [
        {"name": "single-payload", "uris": [single], "batchId": 123456, "entries": [
            ok(parsed("totp", "Example", "alice", b32(s1))),
            ok(parsed("hotp", "", "bob", b32(s2), "SHA256", 8, 30, 5)),
            ok(parsed("totp", "GitHub", "carol", b32(s3))),
            {"ok": False, "error": "INVALID_ALGORITHM", "issuer": "Legacy", "account": "md5"},
            ok(parsed("totp", "Example", "Other:dave", b32(s1), "SHA512", 8)),
        ]},
        {"name": "two-part-batch", "uris": batch, "batchId": -5, "entries": [
            ok(parsed("totp", "A", "one", b32(s1))), ok(parsed("totp", "B", "two", b32(s2)))]},
        {"name": "truncated-protobuf", "uris": [truncated], "error": "MIGRATION_DECODE_FAILED"},
        {"name": "wrong-scheme", "uris": ["otpauth-migration://online?data=AA"], "error": "INVALID_URI"},
    ]


def build() -> dict:
    words = WORDLIST.read_text().split("\n")[:-1]
    assert hashlib.sha256(WORDLIST.read_bytes()).hexdigest() == WORDLIST_SHA256 and len(words) == 2048
    ref = argon2id(b"password", b"somesalt", m=65536, t=2, p=1)
    assert ref.hex() == "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"
    items = gen_items()
    return {
        "$comment": "Generated by scripts/gen_test_vectors.py from spec/crypto.md. Do not edit by hand.",
        "specVersion": 1,
        "argon2id": {"reference": [{"passwordUtf8": "password", "saltUtf8": "somesalt", "m": 65536, "t": 2, "p": 1,
                                    "length": 32, "hashHex": h(ref), "note": "Argon2 reference KAT (phc-winner-argon2)"}]},
        "hkdf": gen_hkdf(),
        "keyHierarchy": gen_key_hierarchy(),
        "fakeSalt": gen_fake_salt(),
        "recovery": gen_recovery(words),
        "padding": gen_padding(),
        "items": items,
        "tamper": gen_tamper(items),
        "invalidEnvelopes": gen_invalid_envelopes(items),
        "kdfParamsRejected": gen_kdf_rejected(),
        "backup": gen_backup(items),
        "otp": gen_otp(),
    }


def main() -> int:
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if OUT.read_text(encoding="utf-8") != text:
            print("spec/test-vectors.json is out of date; run scripts/gen_test_vectors.py", file=sys.stderr)
            return 1
        print("spec/test-vectors.json is up to date")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
