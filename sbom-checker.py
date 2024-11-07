# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import jsonschema
from pathlib import Path
from referencing import Registry, Resource

parser = argparse.ArgumentParser(description='проверка sbom-файлов')
parser.add_argument('json', help='файл-спецификация; по умолчанию ./schema.json', nargs='?', default='./schema.json')
parser.add_argument('filename', help='входной файл в формате CycloneDX JSON для проверки')
parser.add_argument('-e', '--errors', type=int, default=10,
                    help='максимальное число ошибок для вывода; по умолчанию 10; установите 0 для вывода всех ошибок')

args = parser.parse_args()
with open(args.json) as f:
    schema = json.load(f)

registry = None
if Path(args.json).samefile(Path('./schema.json')): # to resolve references to schemas on local filesystem
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

with open(args.filename) as f:
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
        if count == 0:
            print('файл корректный')
    except jsonschema.exceptions.SchemaError as se:
        print('ошибка в файле-спецификации:')
        print(se)
