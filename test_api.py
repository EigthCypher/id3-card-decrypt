#!/usr/bin/env python3
"""Check the library contract in API.md.

Usage:
    python3 test_api.py              # check the modules next to this file
    python3 test_api.py <folder>     # check a flat copy of the run-time modules
                                     # (e.g. where a program installed them)

Every check is one promise from API.md. Exit code 0 = all kept. Uses the
test cards (test_cards/ or $ID3_TEST_CARDS) for the card checks.
"""
import ast
import contextlib
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODULES_DIR = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else HERE

RESULTS = []


def check(condition, message):
    """Record and print one result."""
    RESULTS.append(bool(condition))
    print(('PASS ' if condition else 'FAIL ') + message)


# ---------------------------------------------------------------- shipping --

def module_imports(path):
    """Top-level module names a file imports (anywhere in the file)."""
    tree = ast.parse(open(path, encoding='utf-8').read())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split('.')[0])
    return names


def parses_as_python37(path):
    """True if the file uses no syntax newer than Python 3.7 (checkable on
    Python 3.8+; on older versions the file simply has to compile)."""
    source = open(path, encoding='utf-8').read()
    try:
        ast.parse(source, feature_version=(3, 7))
    except TypeError:            # Python < 3.8: no feature_version
        compile(source, path, 'exec')
    except SyntaxError:
        return False
    return True


sys.path.insert(0, MODULES_DIR)
stdout_before = sys.stdout
captured = io.StringIO()
with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
    import id3_common
    import id3_cipher            # noqa: F401  (imported lazily by id3_common)
    import id3_timeattack        # noqa: F401
    import card_to_json
    import card_export
    import json_to_card

check(isinstance(id3_common.API_VERSION, int) and id3_common.API_VERSION >= 1,
      'API_VERSION is %r' % id3_common.API_VERSION)
runtime = list(id3_common.RUNTIME_MODULES)
check(all(os.path.isfile(os.path.join(MODULES_DIR, name)) for name in runtime),
      'every RUNTIME_MODULES file is present: %s' % ' '.join(runtime))
own = {name[:-3] for name in runtime}
stdlib = getattr(sys, 'stdlib_module_names', None)     # Python 3.10+
for name in runtime:
    path = os.path.join(MODULES_DIR, name)
    if not os.path.isfile(path):
        continue
    foreign = module_imports(path) - own
    if stdlib is not None:
        foreign = {m for m in foreign if m not in stdlib}
    else:                                              # older Python: best effort
        foreign = {m for m in foreign if m in ('numpy', 'serial', 'smartcard', 'requests')}
    check(not foreign, '%s imports only the standard library and the run-time modules%s'
          % (name, '' if not foreign else ' (also: %s)' % ', '.join(sorted(foreign))))
    check(parses_as_python37(path), '%s runs on Python 3.7' % name)
check(captured.getvalue() == '' and sys.stdout is stdout_before, 'importing prints nothing and leaves stdout alone')

# ------------------------------------------------------------------- cards --

cards = [path for _, path in id3_common.known_cards()]   # (card id, path) pairs
check(len(cards) > 0, '%d test cards found' % len(cards))

DECODE_KEYS = {'cipher_seed', 'raw_hex', 'name', 'car', 'key_number', 'points', 'plays_remaining',
               'dr_level', 'is_manual', 'color', 'steering', 'bgm', 'bgm_num', 'navi', 'time_disp',
               'force_end', 'win', 'lose', 'win_cont', 'level', 'vslv_max', 'vs_exp', 'round',
               'tuning', 'bunta_levels', 'areas_beaten', 'time_attack', 'npc_details'}
TUNING_PARTS = {'pow', 'fsp', 'bon', 'mir', 'sid', 'bmp', 'rsp', 'muf', 'whl', 'stk', 'e1e2'}
BUNTA_COURSES = {'Akagi', 'Akina', 'Happogahara', 'Irohazaka', 'slot4', 'slot5', 'slot6', 'slot7'}
EXTRACT_KEYS = {'name', 'manufacturer', 'car_name', 'car_idx', 'key_number', 'areas_str', 'areas_count',
                'racer_level', 'card_image', 'points', 'win', 'lose', 'is_manual', 'tuning', 'bunta',
                'npc_defeated', 'plays_remaining'}

problems = {'load': [], 'keys': [], 'types': [], 'extract': [], 'roundtrip': [], 'edit': []}
for path in cards:
    label = os.path.basename(path)
    original = open(path, 'rb').read()
    try:
        plain, seed = id3_common.load_and_decrypt(path)
    except ValueError:
        problems['load'].append(label)
        continue
    if len(plain) != 195 or not isinstance(seed, int):
        problems['load'].append(label)
        continue
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        card = card_to_json.decode_card_to_dict(plain, None, seed)
        fields = card_export.extract_fields(plain)
        same = json_to_card.encode_card({'raw_hex': card['raw_hex']})
        # A typical edit: a few fields, partial tuning / Bunta dicts.
        edited = json_to_card.encode_card({'raw_hex': card['raw_hex'], 'points': 1234,
                                           'car': {'index': 6}, 'tuning': {'pow': 5},
                                           'bunta_levels': {'Akina': 3}, 'name': 'ABC'})
        after = card_to_json.decode_card_to_dict(edited, None, seed)

    missing = (DECODE_KEYS | set(id3_common.WORD_FIELDS)) - set(card)
    if missing or set(card['tuning']) != TUNING_PARTS or set(card['bunta_levels']) != BUNTA_COURSES \
            or set(card['car']) < {'index', 'name'} or len(card['areas_beaten']) != 9:
        problems['keys'].append(label)
    if not (isinstance(card['cipher_seed'], str) and int(card['cipher_seed'], 16) == seed
            and isinstance(card['name'], str) and isinstance(card['car']['index'], int)
            and all(isinstance(card[k], int) for k in id3_common.WORD_FIELDS)):
        problems['types'].append(label)
    if not (EXTRACT_KEYS <= set(fields) and len(fields['areas_str']) == 9
            and set(fields['areas_str']) <= {'0', '1'} and fields['racer_level'] == card['dr_level']
            and fields['card_image'].startswith('card') and fields['card_image'].endswith('.png')):
        problems['extract'].append(label)
    frame = id3_common.wrap_protocol_frame(id3_common.encrypt_card(same, seed))
    if same != plain or (len(original) == 215 and frame != original):
        problems['roundtrip'].append(label)
    kept = {k: v for k, v in after['tuning'].items() if k != 'pow'} == \
        {k: v for k, v in card['tuning'].items() if k != 'pow'}
    if not (after['points'] == 1234 and after['car']['index'] == 6 and after['tuning']['pow'] == 5
            and after['bunta_levels']['Akina'] == 3 and after['name'] == 'ABC' and kept
            and after['time_attack'] == card['time_attack'] and after['npc_details'] == card['npc_details']):
        problems['edit'].append(label)

check(not problems['load'], 'load_and_decrypt: (195-byte plaintext, int seed) for every card %s' % problems['load'])
check(not problems['keys'], 'decode_card_to_dict: every promised key %s' % problems['keys'])
check(not problems['types'], 'decode_card_to_dict: promised value types %s' % problems['types'])
check(not problems['extract'], 'extract_fields: every promised key %s' % problems['extract'])
check(not problems['roundtrip'], 'raw_hex round trip and re-encryption are exact %s' % problems['roundtrip'])
check(not problems['edit'], 'encode_card: edits land, partial dicts and other data kept %s' % problems['edit'])

# Damaged and wrong-size files are refused with ValueError.
damaged_ok = True
if cards:
    import tempfile
    good = open(cards[0], 'rb').read()
    for bad in (good[:100] + bytes([good[100] ^ 1]) + good[101:], good[:-1], b'x' * 300):
        with tempfile.NamedTemporaryFile(suffix='.card', delete=False) as temp:
            temp.write(bad)
        try:
            id3_common.load_and_decrypt(temp.name)
            damaged_ok = False
        except ValueError:
            pass
        finally:
            os.remove(temp.name)
check(damaged_ok, 'load_and_decrypt raises ValueError for a damaged frame and wrong sizes')

check(isinstance(id3_common.CAR_MODELS, dict) and set(id3_common.CAR_MODELS) == set(id3_common.CAR_MANUFACTURER)
      and all(isinstance(k, int) and isinstance(v, str) for k, v in id3_common.CAR_MODELS.items()),
      'CAR_MODELS and CAR_MANUFACTURER: same int keys, str values')

failed = RESULTS.count(False)
print('API %d: %d passed, %d failed' % (id3_common.API_VERSION, RESULTS.count(True), failed))
sys.exit(1 if failed else 0)
