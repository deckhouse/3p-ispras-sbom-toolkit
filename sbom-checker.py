# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import jsonschema
from pathlib import Path

parser = argparse.ArgumentParser(description='проверка sbom-файлов')
parser.add_argument('json', help='файл-спецификация; по умолчанию ./schema.json', nargs='?', default='./schema.json')
parser.add_argument('filename', help='входной файл в формате CycloneDX JSON для проверки')
parser.add_argument('-e', '--errors', type=int, default=10,
                    help='максимальное число ошибок для вывода; по умолчанию 10; установите 0 для вывода всех ошибок')

args = parser.parse_args()
with open(args.json) as f:
    schema = json.load(f)

if Path(args.json).samefile(Path('./schema.json')): # to resolve references to schemas on local filesystem
    schema["$defs"]["license"]["properties"]["id"]["$ref"] = \
        "file://" + str(Path(__file__).parent.resolve() / 'additional_schemas' / \
        schema["$defs"]["license"]["properties"]["id"]["$ref"])
    schema["$defs"]["signature"]["$ref"] = \
        "file://" + str(Path(__file__).parent.resolve() / 'additional_schemas' / \
        schema["$defs"]["signature"]["$ref"])

with open(args.filename) as f:
    try:
        parsed_file = json.load(f)
        cls = jsonschema.validators.validator_for(schema)
        cls.check_schema(schema)
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
