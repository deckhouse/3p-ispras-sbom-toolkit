# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import jsonschema
import logging
from pathlib import Path
from referencing import Registry, Resource

from sbom_utils import check_repo, opener, parse_repo_url, load_cache, dump_cache

parser = argparse.ArgumentParser(description='проверка sbom-файлов')
parser.add_argument('filename', help='входной файл в формате CycloneDX JSON для проверки')
parser.add_argument('-e', '--errors', type=int, default=10,
                    help='максимальное число ошибок для вывода; по умолчанию 10; установите 0 для вывода всех ошибок')
parser.add_argument('--check-vcs', action='store_true', help='проверка url типа vcs на git/svn/hg-репозиторий (требуется доступ к Интернет и наличие пакетов git, subversion и mercurial)')
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
        repo_dict = load_cache()
        while stack:
            component = stack.pop(0)
            stack += component.get('components', [])
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
                            repo_dict[url], ex_str = check_repo(url, _git)
                            if not repo_dict[url]:
                                logging.info(ex_str)
                                not_repos += 1
                                print(f"WARNING: {ref.get('url', '')} не подходит под шаблон и не является git/svn/hg-репозиторием")
                                print('-'*50)
        dump_cache({k:v for k,v in repo_dict.items() if v})
        if not_repos == 0 and count == 0:
            print('файл корректный')
    elif count == 0:
        print('файл корректный')
except jsonschema.exceptions.SchemaError as se:
    print('ошибка в файле-спецификации:')
    print(se)
