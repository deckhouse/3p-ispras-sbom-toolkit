# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import jsonschema
from pathlib import Path
import re
from referencing import Registry, Resource
import urllib.parse

def parse_repo_url(url):
    parsed_url = urllib.parse.urlparse(url)
    path = parsed_url.path.strip('/')
    query = urllib.parse.parse_qs(parsed_url.query)
    if 'commit' in query:
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), query['commit'][0]
    if parsed_url.netloc == 'src.libcode.org':
        r = r"(.+)\/(src)\/(.+)"
    elif 'gitlab' in parsed_url.netloc:
        r = r"(.+)\/-\/(commit|tags|tree)\/(.+)"
    else:
        r = r"(.+)\/(commit|blob|tree|releases\/tag)\/(.+)"
    m1 = re.match(r, path)
    if m1:
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + m1.group(1)), m1.group(3)
    return None

parser = argparse.ArgumentParser(description='проверка sbom-файлов')
parser.add_argument('filename', help='входной файл в формате CycloneDX JSON для проверки')
parser.add_argument('-e', '--errors', type=int, default=10,
                    help='максимальное число ошибок для вывода; по умолчанию 10; установите 0 для вывода всех ошибок')
parser.add_argument('--check-vcs', action='store_true', help='проверка url типа vcs на git-репозиторий (требуется доступ к Интернет)')

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
                for ref in component.get('externalReferences', []):
                    if ref.get('type', '') == 'vcs':
                        url = ref.get('url', '')
                        res = parse_repo_url(url)
                        if res:
                            url = res[0]
                        if not url in repo_dict:
                            try:
                                ls_res = _git.ls_remote(url)
                                repo_dict[url] = True
                            except Exception:
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
