# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import jsonschema
from pathlib import Path
from referencing import Registry, Resource

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
            print(err)
            print('-'*50)
            if limit and count == limit:
                break
        if args.check_vcs:
            from git.cmd import Git
            _git = Git()
            stack = parsed_file.get('components', []).copy()
            not_repos = 0
            while stack:
                component = stack.pop(0)
                for url in component.get('externalReferences', []):
                    if url.get('type', '') == 'vcs':
                        try:
                            ls_res = _git.ls_remote(url.get('url', ''))
                        except Exception:
                            not_repos += 1
                            print(f"{url['url']} не является git-репозиторием")
                            print('-'*50)
            if not_repos == 0 and count == 0:
                print('файл корректный')
        elif count == 0:
            print('файл корректный')
    except jsonschema.exceptions.SchemaError as se:
        print('ошибка в файле-спецификации:')
        print(se)
