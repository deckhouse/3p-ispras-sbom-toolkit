from collections import Counter
import json

def validate_no_duplicate_keys(list_of_pairs):
    key_count = Counter(k for k,v in list_of_pairs)
    duplicate_keys = ', '.join(k for k,v in key_count.items() if v>1)

    if len(duplicate_keys) != 0:
        raise ValueError(f'Duplicate key(s) in file: {duplicate_keys}')
    return dict(list_of_pairs)

def opener(filename, pairs=False):
    encoding = None
    try:
        with open(filename) as f:
            data = json.load(f, object_pairs_hook=(validate_no_duplicate_keys if pairs else None))
    except UnicodeDecodeError:
        with open(filename, encoding='utf-8') as f: # duplicate keys detection
            data = json.load(f, object_pairs_hook=(validate_no_duplicate_keys if pairs else None))
        encoding = 'utf-8'
    except json.decoder.JSONDecodeError:
        with open(filename, encoding='utf-8-sig') as f: # duplicate keys detection
            data = json.load(f, object_pairs_hook=(validate_no_duplicate_keys if pairs else None))
        encoding = 'utf-8-sig'
    return data, encoding