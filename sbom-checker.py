# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import jsonschema

parser = argparse.ArgumentParser(description='json schema checker')
parser.add_argument('json', help='schema file', nargs='?', default='./schema.json')
parser.add_argument('filename', help='file to check')
parser.add_argument('-e', '--errors', type=int, default=10,
                    help='set maximum amount of validator errors shown; default is 10; set to 0 to show all errors')

args = parser.parse_args()
with open(args.json) as f:
    schema = json.load(f)
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
            print('file is valid')
    except jsonschema.exceptions.SchemaError as se:
        print('schema error:')
        print(se)
