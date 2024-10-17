# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import json

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

args = parser.parse_args()
with open(args.input, 'r') as f:
    input_data = json.load(f)

if args.props:
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

    with open(args.output, 'w') as f:
        json.dump(input_data, f, indent=2)