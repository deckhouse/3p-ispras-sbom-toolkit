# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import concurrent.futures
import json
import jsonschema
import logging
from pathlib import Path
import re
from referencing import Registry, Resource

from sbom_utils import check_repo, opener, parse_repo_url, load_cache, dump_cache

parser = argparse.ArgumentParser(description='проверка sbom-файлов')
parser.add_argument('filename', help='входной файл в формате CycloneDX JSON для проверки')
parser.add_argument('-e', '--errors', type=int, default=10,
                    help='максимальное число ошибок для вывода; по умолчанию 10; установите 0 для вывода всех ошибок')
parser.add_argument('--check-vcs', action='store_true', help='проверка url типа vcs на git/svn/hg/fossil-репозиторий (требуется доступ к Интернет и наличие пакетов git, subversion и mercurial)')
parser.add_argument('--check-vcs-leaf-only', action='store_true', help='то же, что и --check-vcs, но проверяются только url в листовых компонентах')
parser.add_argument('-v', '--verbose', action='store_true', help='подробный вывод')

with open(Path(__file__).parent.resolve() / 'schema.json') as f:
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

# encoding and duplicate keys detection
data, encoding = opener(args.filename, pairs=True)

with open(args.filename, encoding=encoding) as f:
    parsed_file = json.load(f)
try:
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
        if err.message.endswith(' has non-unique elements'):
            p = re.compile('(?<!\\\\)\'')
            arr = json.loads(p.sub('\"', err.message[:-24]))
            dups = []
            for n, i in enumerate(arr):
                if i in arr[n+1:] and not i in dups:
                    dups.append(i)
            inst = ''
            for line in str(err).split('\n'):
                if line.startswith('On instance'):
                    inst = line[:-1]
                    break
            print(f'ERROR: {inst} non-unique elements:\n' + '\n'.join([str(x) for x in dups]))
        else:
            print("ERROR: " + str(err))
        print('-'*50)
        if limit and count == limit:
            break
    if args.check_vcs or args.check_vcs_leaf_only:
        import os
        os.environ['GIT_TERMINAL_PROMPT'] = '0'
        stack = parsed_file.get('components', []).copy()
        not_repos = 0
        repo_dict = load_cache()
        refs_to_check = dict()
        while stack:
            component = stack.pop(0)
            stack += component.get('components', [])
            if args.check_vcs_leaf_only and component.get('components', []):
                continue
            refs = component.get('externalReferences', [])
            if type(refs) == list:
                for ref in refs:
                    if type(ref) == dict and ref.get('type', '') == 'vcs':
                        url = ref.get('url', '')
                        res = parse_repo_url(url)
                        if res and res[1]:
                            url = res[0]
                        ex_str = ''
                        if not url in repo_dict:
                            if not url in refs_to_check:
                                refs_to_check[url] = set()
                            refs_to_check[url].add(ref.get('url', ''))
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_url = {executor.submit(check_repo, url): url for url in refs_to_check.keys()}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    repo_dict[url], ex_str = future.result()
                except Exception as exc:
                    print('ERROR: %r generated an exception: %s' % (url, exc))
                else:
                    if not repo_dict[url]:
                        not_repos += len(refs_to_check[url])
                        for u in sorted(list(refs_to_check[url])):
                            logging.info(ex_str)
                            print(f"WARNING: {u} не подходит под шаблон и не является git/svn/hg/fossil-репозиторием")
                            print('-'*50)
        dump_cache({k:v for k,v in repo_dict.items() if v})
        if not_repos == 0 and count == 0:
            print('файл корректный')
    elif count == 0:
        print('файл корректный')
except jsonschema.exceptions.SchemaError as se:
    print('ошибка в файле-спецификации:')
    print(se)
