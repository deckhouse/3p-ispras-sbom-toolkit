# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
from collections import Counter
import json
import jsonschema
import logging
from pathlib import Path
import re
from referencing import Registry, Resource
import urllib.parse

def validate_no_duplicate_keys(list_of_pairs):
    key_count = Counter(k for k,v in list_of_pairs)
    duplicate_keys = ', '.join(k for k,v in key_count.items() if v>1)

    if len(duplicate_keys) != 0:
        raise ValueError(f'Duplicate key(s) in file: {duplicate_keys}')
    return dict(list_of_pairs)

pattern_dict = {
    'src.libcode.org': ((), ('src', 'commit')),
    'codeberg.org': ((('src', 'branch'), ('src', 'commit'), ('src', 'tag'), ('releases', 'tag')), ('commit',)),
    'opendev.org': ((('src', 'branch'), ('src', 'commit'), ('src', 'tag'), ('releases', 'tag')), ('commit',)),
    'bitbucket.org': ((), ('commits', 'src', 'branch')),
    'sourceforge.net': ((), ('ci',)),
}

def parse_repo_url(url):
    parsed_url = urllib.parse.urlparse(url)
    path = parsed_url.path.strip('/')
    query = urllib.parse.parse_qs(parsed_url.query)
    if 'commit' in query:
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), query['commit'][0]
    if 'tag' in query:
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), query['tag'][0]
    path_pair_list = []
    path_split = path.split('/')
    for idx in range(len(path_split) - 1):
        path_pair_list.append((path_split[idx], path_split[idx+1]))
    idx = -1
    flag = 0
    if parsed_url.netloc in pattern_dict:
        for s in pattern_dict[parsed_url.netloc][0]:
            if s in path_pair_list:
                idx = path_pair_list.index(s)
                flag = 1
                break
        else:
            for s in pattern_dict[parsed_url.netloc][1]:
                if s in path_split:
                    idx = path_split.index(s)
                    break
    else:
        for s in [('-', 'commit'), ('-', 'tags'), ('-', 'tree'), ('-', 'blob'), ('releases', 'tag')]:
            if s in path_pair_list:
                idx = path_pair_list.index(s)
                flag = 1
                break
        else:
            for s in ['commit', 'blob', 'tree']:
                if s in path_split:
                    idx = path_split.index(s)
                    break
    if idx > 0:
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + '/'.join(path_split[:idx])), '/'.join(path_split[idx+1+flag:])
    return None

parser = argparse.ArgumentParser(description='проверка sbom-файлов')
parser.add_argument('filename', help='входной файл в формате CycloneDX JSON для проверки')
parser.add_argument('-e', '--errors', type=int, default=10,
                    help='максимальное число ошибок для вывода; по умолчанию 10; установите 0 для вывода всех ошибок')
parser.add_argument('--check-vcs', action='store_true', help='проверка url типа vcs на git-репозиторий (требуется доступ к Интернет)')
parser.add_argument('-v', '--verbose', action='store_true', help='побробный вывод')

with open('./schema.json') as f:
    schema = json.load(f)

registry = None
with open(Path(__file__).parent.resolve() / 'additional_schemas' / "spdx.schema.json") as f:
    resource1 = Resource.from_contents(json.load(f))
with open(Path(__file__).parent.resolve() / 'additional_schemas' / "jsf-0.82.schema.json") as f:
    resource2 = Resource.from_contents(json.load(f))
registry = Registry().with_resources(
    [
        ("spdx.schema.json", resource1),
        ("jsf-0.82.schema.json", resource2),
    ],
)

args = parser.parse_args()
if args.verbose:
    logging.basicConfig(format='%(message)s', level="INFO")
with open(args.filename, encoding='utf-8') as f: # duplicate keys detection
    json.load(f, object_pairs_hook=validate_no_duplicate_keys)
with open(args.filename, encoding='utf-8') as f:
    try:
        parsed_file = json.load(f)
        cls = jsonschema.validators.validator_for(schema)
        cls.check_schema(schema)
        if registry:
            validator = cls(schema, format_checker=cls.FORMAT_CHECKER, registry=registry)
        else:
            validator = cls(schema, format_checker=cls.FORMAT_CHECKER)
        errors = validator.iter_errors(parsed_file)
        count = 0
        limit = args.errors
        for err in errors:
            count += 1
            print("ERROR: " + str(err))
            print('-'*50)
            if limit and count == limit:
                break
        if args.check_vcs:
            from git.cmd import Git
            import os
            os.environ['GIT_TERMINAL_PROMPT'] = '0'
            _git = Git()
            stack = parsed_file.get('components', []).copy()
            not_repos = 0
            repo_dict = {'': False}
            while stack:
                component = stack.pop(0)
                stack += component.get('components', [])
                refs = component.get('externalReferences', [])
                if type(refs) == list:
                    for ref in refs:
                        if type(ref) == dict and ref.get('type', '') == 'vcs':
                            url = ref.get('url', '')
                            res = parse_repo_url(url)
                            if res:
                                url = res[0]
                            if not url in repo_dict:
                                try:
                                    ls_res = _git.ls_remote(url)
                                    repo_dict[url] = True
                                except Exception as e:
                                    logging.info(e)
                                    repo_dict[url] = False
                            if not repo_dict[url]:
                                not_repos += 1
                                print(f"WARNING: {ref.get('url', '')} не является git-репозиторием и не подходит под шаблон")
                                print('-'*50)
            if not_repos == 0 and count == 0:
                print('файл корректный')
        elif count == 0:
            print('файл корректный')
    except jsonschema.exceptions.SchemaError as se:
        print('ошибка в файле-спецификации:')
        print(se)
