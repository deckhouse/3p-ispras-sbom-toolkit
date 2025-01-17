# SPDX-FileCopyrightText: 2024 Artem Irkhin
# SPDX-License-Identifier: Apache-2.0

import csv, argparse

from sbom_utils import opener

def get_prop(arr, name):
    for elem in arr:
        if elem.get('name', '') == name:
            return elem.get('value', '')
    return ''


parser = argparse.ArgumentParser(description='генератор таблицы компонентов в формате csv')
parser.add_argument('input', help='входной файл, содержащий перечень заимствованных компонентов, в JSON формате')
parser.add_argument('output', help='выходной файл в формате csv, содержащий таблицу со всеми компонентами из входного файла')
args = parser.parse_args()

bom_json, encoding = opener(args.input)

with open(args.output, 'w', newline="") as file:
    writer = csv.writer(file)
    writer.writerow(['№ п/п','Наименование компонента', 'Версия компонента', 'Язык (языки) программирования, на котором написан компонент', 'Принадлежность компонента к поверхности атаки программного обеспечения и (или) к компонентам, реализующим функции безопасности', 'Адрес веб-ресурса, на котором расположен исходный код компонента'])

stack = bom_json.get('components', []).copy()
idx = 1
added_elements = set()

while stack:
    component = stack.pop(0)
    if 'components' in component:
        stack += component['components']

    ext_refs = component.get('externalReferences')
    urls = ''
    if ext_refs:
        for item in ext_refs:
            if item['type'] == 'vcs':
                urls+=f'Репозиторий: {item["url"]}\n'
            elif item['type'] == 'website':
                urls+=f'Адрес веб-ресурса компонента: {item["url"]}\n'
            else:
                urls+=f'Иное: {item["url"]}\n'
    special_function = {"GOST:attack_surface":"yes/indirect/no", "GOST:security_function":"yes/indirect/no"}
    props = component.get('properties', [])
    attack_surface = get_prop(props, 'GOST:attack_surface')
    if attack_surface in ['yes', 'indirect', 'no']: special_function["GOST:attack_surface"] = attack_surface
    security_function = get_prop(props, 'GOST:security_function')
    if security_function in ['yes', 'indirect', 'no']: special_function["GOST:security_function"] = security_function
    element = (component['name'], component['version'], get_prop(props, 'source_langs'), special_function, urls)
    if element in added_elements:
        continue
    added_elements.add(element)
    with open(args.output, 'a', newline="") as file:
        writer = csv.writer(file)
        writer.writerow([idx, component['name'], component['version'], get_prop(props, 'source_langs'), special_function, urls])
    idx += 1


