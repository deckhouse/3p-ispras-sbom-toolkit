# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import jsonschema

parser = argparse.ArgumentParser(description='json schema checker')
parser.add_argument('json', help='schema file', nargs='?', default='./schema.json')
parser.add_argument('filename', help='file to check')

args = parser.parse_args()
with open(args.json) as f:
    SCHEMA = json.load(f)
with open(args.filename) as f:
    try:
        parsed_file = json.load(f)
        jsonschema.validate(parsed_file, SCHEMA, format_checker=jsonschema.Draft7Validator.FORMAT_CHECKER)
        print('file is valid')
    except jsonschema.exceptions.ValidationError as ve:
        print(ve.message)
