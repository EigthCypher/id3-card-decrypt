# Library API (contract for programs that import these modules)

The command-line tools in this repository are for people. Other programs can also import the card modules directly. This file is the contract for them: what stays the same between releases, and how a change is announced.

- **API version:** `id3_common.API_VERSION`, now **1**.
- **Checked by:** `python3 test_api.py`, which exits 0 if this repository keeps every promise below. Run it before tagging a release; a program that bundles these modules can run it too.

## Versions and releases

- Releases are git tags `v<API_VERSION>.<n>`, e.g. `v1.0`, `v1.1`. Pin a tag, not a branch.
- Within one API version, releases only **add**: new functions, new keys in returned dicts, new optional arguments, fixes to decoded values (a field decoded wrongly before is decoded correctly now).
- Anything that removes, renames or changes the meaning of something listed here raises `API_VERSION` and starts a new tag series (`v2.0`). The change is described at the top of this file under "Changes".
- `test_api.py` is part of the contract: a release whose `test_api.py` fails is not a release.

## Shipping

- The run-time files are listed in `id3_common.RUNTIME_MODULES`:
  `id3_common.py id3_cipher.py id3_timeattack.py card_to_json.py card_export.py json_to_card.py`.
  Copy them into one folder (flat) and put that folder on `sys.path`. Nothing else is needed at run time.
- The run-time files use only the Python standard library and each other, and run on **Python 3.7** or later.
- Importing them prints nothing, writes no files and leaves `sys.stdout` alone. (Some add their own folder to `sys.path`, so they find each other.)
- Development material, not for shipping: the command-line tools (`show_card.py`, `reset_plays.py`, ...), `test_*.py`, `analysis/` and `test_cards/`. `test_cards/` holds real card dumps.

## Functions

All bytes are `bytes`; "plaintext" is the 195-byte decrypted card, "body" the 207-byte encrypted card, "frame" the 215-byte serial frame (body wrapped with start byte, header, end byte and checksum).

| Function | Promise |
|---|---|
| `id3_common.load_and_decrypt(path)` | Reads a card file (215-byte frame or 207-byte body) and returns `(plaintext, cipher_seed)`, `cipher_seed` an `int`. Raises `ValueError` for any other size, and for a frame with wrong start/end bytes or a wrong checksum (a damaged card). |
| `id3_common.encrypt_card(plaintext, cipher_seed)` | Returns the body. With the seed from `load_and_decrypt`, reproduces the original body exactly. |
| `id3_common.wrap_protocol_frame(body)` | Returns the frame, checksum included. |
| `card_to_json.decode_card_to_dict(plaintext, card_id=None, cipher_seed=0)` | Returns the card as a JSON-ready dict (keys below). |
| `json_to_card.encode_card(card_dict)` | Returns the plaintext for a dict shaped like `decode_card_to_dict`'s. Every key is optional; with `raw_hex`, missing keys and bits nobody has decoded keep their value. `encode_card({"raw_hex": d["raw_hex"]})` gives back the same plaintext. Raises `ValueError` for a value that cannot be stored as given. May print warnings to stdout/stderr (redirect them if output matters). |
| `card_export.extract_fields(plaintext)` | Returns a flat summary dict (keys below). |
| `id3_common.CAR_MODELS`, `id3_common.CAR_MANUFACTURER` | `{car index (int): str}`: model name, and the maker line printed on the card. Same keys in both. |

The full round trip is always exact:
`wrap_protocol_frame(encrypt_card(encode_card(decode_card_to_dict(p, None, s)), s)) == original frame`.

## Keys

### `decode_card_to_dict()`

Every key it returns today is stable (new keys may be added). The ones most programs need:

| Key | Value |
|---|---|
| `cipher_seed` | `str`, `"0x%08x"`; `int(value, 16)` is the seed for `encrypt_card` |
| `raw_hex` | `str`, the plaintext as hex |
| `name` | `str`, the driver name (blank padding removed) |
| `car` | `{"index": int, "name": str}`. In `encode_card` both `{"index": n}` and `n` are accepted |
| `key_number`, `points`, `plays_remaining`, `dr_level` (racer level) | `int` |
| `is_manual`, `color`, `steering`, `bgm`, `bgm_num`, `navi`, `time_disp`, `force_end` | `int` (option settings) |
| `win`, `lose`, `win_cont`, `level`, `vslv_max`, `vs_exp`, `round` | `int` (versus / Bunta challenge) |
| `tuning` | `{part: int}` for `pow fsp bon mir sid bmp rsp muf whl stk e1e2`. In `encode_card` a partial dict changes only the parts given |
| `bunta_levels` | `{course: int}` for `Akagi Akina Happogahara Irohazaka slot4 slot5 slot6 slot7`. Partial dicts as for `tuning` |
| `areas_beaten` | `{course name: bool}`, 9 entries in course order |
| `time_attack`, `npc_details` | Opaque to most programs: compare them, or pass them back to `encode_card` unchanged |

Every name in `id3_common.WORD_FIELDS` is also a key, with an `int` value.

### `extract_fields()`

`name`, `manufacturer`, `car_name`, `car_idx`, `key_number`, `areas_str` (9 characters `0`/`1`, course 0 first), `areas_count`, `racer_level` (same as `dr_level`), `card_image` (`cardN.png`), `points`, `win`, `lose`, `is_manual`, `tuning`, `bunta`, `npc_defeated`, `plays_remaining`.

## Changes

- **API 1 (`v1.0`)**: first version of this contract, describing the modules as of commit `3950c17`.
