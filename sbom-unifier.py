# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import datetime
import json
from pathlib import Path

from sbom_utils import opener

def get_prop(arr, name):
    for elem in arr:
        if elem.get('name', '') == name:
            return elem.get('value', '')
    return ''

def eval_prop(components, name):
    vals = set()
    for comp in components:
        vals.add(get_prop(comp.get('properties', []), name))
    if 'yes' in vals:
        return 'yes'
    if 'indirect' in vals:
        return 'indirect'
    if vals == {'no'}:
        return 'no'
    return ''

parser = argparse.ArgumentParser(description='объединение sbom-файлов')
parser.add_argument('--app-name', required=True, help='название продукта')
parser.add_argument('--app-version', required=True, help='версия продукта')
parser.add_argument('--manufacturer', required=True, help='название организации — изготовителя продукта')
parser.add_argument('input', nargs='+', help='перечень входных файлов в формате CycloneDX JSON для объединения; рекомендуется использовать файлы, проверенные скриптом sbom-checker.py')
parser.add_argument('output', help='выходной файл, в котором продукты из входных файлов объединены в список компонентов')

with open(Path(__file__).parent.resolve() / 'schema.json') as f:
    schema = json.load(f)
    keys = set(schema['properties']).intersection(schema['$defs']['component']['properties'])
    if 'version' in keys:
        keys.remove('version')
    if 'name' in keys:
        keys.remove('name')
    if 'type' in keys:
        keys.remove('type')

args = parser.parse_args()
all_components = []
for fn in args.input:
    data, encoding = opener(fn)
    new_data = data['metadata']['component'].copy()
    for key in keys:
        if key in data:
            new_data[key] = data[key]
    if not 'properties' in new_data:
        new_data['properties'] = []
    if not get_prop(new_data.get('properties', []), 'GOST:attack_surface'):
        new_data['properties'].append({
            "name": 'GOST:attack_surface',
            "value": eval_prop(data.get('components', []), 'GOST:attack_surface')
        })
    if not get_prop(new_data.get('properties', []), 'GOST:security_function'):
        new_data['properties'].append({
            "name": 'GOST:security_function',
            "value": eval_prop(data.get('components', []), 'GOST:security_function')
        })
    all_components.append(new_data)

output_data = {
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "component": {
        "type": "application",
        "name": args.app_name,
        "version": args.app_version,
        "manufacturer": {
            "name": args.manufacturer
        }
    }
  },
  "components": all_components
}

with open(args.output, 'w', encoding=encoding) as f:
    json.dump(output_data, f, indent=2, ensure_ascii=False)