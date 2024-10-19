# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import datetime
import json

DEFAULT_VALUE = "TODO"

def has_prop(arr, name):
    for elem in arr:
        if elem.get('name', '') == name:
            return True
    return False

parser = argparse.ArgumentParser(description='sbom file updater')
parser.add_argument('input', help='sbom file')
parser.add_argument('output', help='updated file')
parser.add_argument('--props', action='store_true',
                    help='add {"name": "GOST:attack_surface", "value": "yes"} and {"name": "GOST:security_function", "value": "yes"} to "properties" property of every component in the input file')
parser.add_argument('--app-name', help='set app name')
parser.add_argument('--app-version', help='set app version')
parser.add_argument('--manufacturer', help='set app manufacturer')
parser.add_argument('--fix-all', action='store_true', help=f'apply all of the above commands; if the required field is missing and its value is not set in command line, "{DEFAULT_VALUE}" is used')

args = parser.parse_args()
with open(args.input, 'r') as f:
    input_data = json.load(f)

if args.props or args.fix_all:
    stack = input_data.get('components', []).copy()
    while stack:
        component = stack.pop()
        if not 'properties' in component:
            component['properties'] = []
        if not has_prop(component['properties'], 'GOST:attack_surface'):
            component['properties'].append({'name': 'GOST:attack_surface', 'value': 'yes'})
        if not has_prop(component['properties'], 'GOST:security_function'):
            component['properties'].append({'name': 'GOST:security_function', 'value': 'yes'})
        if 'components' in component:
            stack += component['components']

if not args.app_name is None or args.fix_all:
    if not 'metadata' in input_data:
        input_data['metadata'] = dict()
    if not 'component' in input_data['metadata']:
        input_data['metadata']['component'] = dict()
    if not args.app_name is None:
        input_data['metadata']['component']['name'] = args.app_name
    elif not 'name' in input_data['metadata']['component']:
        input_data['metadata']['component']['name'] = DEFAULT_VALUE


if not args.app_version is None or args.fix_all:
    if not 'metadata' in input_data:
        input_data['metadata'] = dict()
    if not 'component' in input_data['metadata']:
        input_data['metadata']['component'] = dict()
    if not args.app_version is None:
        input_data['metadata']['component']['version'] = args.app_version
    elif not 'version' in input_data['metadata']['component']:
        input_data['metadata']['component']['version'] = DEFAULT_VALUE

if not args.manufacturer is None or args.fix_all:
    if not 'metadata' in input_data:
        input_data['metadata'] = dict()
    if not 'component' in input_data['metadata']:
        input_data['metadata']['component'] = dict()
    if not 'manufacturer' in input_data['metadata']['component']:
        input_data['metadata']['component']['manufacturer'] = dict()
    if not args.manufacturer is None:
        input_data['metadata']['component']['manufacturer']['name'] = args.manufacturer
    elif not 'name' in input_data['metadata']['component']['manufacturer']:
        input_data['metadata']['component']['manufacturer']['name'] = DEFAULT_VALUE

if 'metadata' in input_data:
    input_data['metadata']['timestamp'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
if 'version' in input_data:
    input_data['version'] += 1
with open(args.output, 'w') as f:
    json.dump(input_data, f, indent=2)