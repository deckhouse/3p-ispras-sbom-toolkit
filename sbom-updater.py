# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import datetime
import git
import json
import logging
from requests import Session, adapters
import xml.etree.ElementTree as ET

DEFAULT_VALUE = "TODO"

def has_prop(arr, name):
    for elem in arr:
        if elem.get('name', '') == name:
            return True
    return False

parser = argparse.ArgumentParser(description='изменение sbom-файлов')
parser.add_argument('input', help='входной файл в формате CycloneDX JSON, содержащий актуальную информацию о составе заимствованных компонентов')
parser.add_argument('output', help='выходной файл с дооформленным переченем заимствованных компонентов')
parser.add_argument('--props', action='store_true',
                    help='добавить {"name": "GOST:attack_surface", "value": "yes"} и {"name": "GOST:security_function", "value": "yes"} в поле "properties" для каждого компонента входного файла, при их отсутствии')
parser.add_argument('--app-name', help='установить название продукта')
parser.add_argument('--app-version', help='установить версию продукта')
parser.add_argument('--manufacturer', help='установить название организации — изготовителя продукта')
parser.add_argument('--ref', action='store_true', help='установить поле "externalReferences", основываясь на поле "purl" компонента')
parser.add_argument('--fix-all', action='store_true', help=f'применить все вышеописанные опции; если необходимое поле остутствует и его значение не указано, используется "{DEFAULT_VALUE}"')
parser.add_argument('--update', metavar='OLD_SBOM', help='предыдущая версия переченя заимствованных компонентов, состав и версии которых могли устареть, но метаинформация о приложении и компонентах по возможности переносится в новый перечень')
parser.add_argument('-v', '--verbose', action='store_true', help='побробный вывод')

args = parser.parse_args()
if args.verbose:
    logging.basicConfig(format='%(message)s', level="INFO")
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
        if 'name' in input_data['metadata']['component']:
            logging.info(f"смена названия продукта {input_data['metadata']['component']['name']} -> {args.app_name}")
            logging.info('-'*50)
        input_data['metadata']['component']['name'] = args.app_name
    elif not 'name' in input_data['metadata']['component']:
        input_data['metadata']['component']['name'] = DEFAULT_VALUE

if not args.app_version is None or args.fix_all:
    if not 'metadata' in input_data:
        input_data['metadata'] = dict()
    if not 'component' in input_data['metadata']:
        input_data['metadata']['component'] = dict()
    if not args.app_version is None:
        if 'version' in input_data['metadata']['component']:
            logging.info(f"смена версии продукта {input_data['metadata']['component']['version']} -> {args.app_version}")
            logging.info('-'*50)
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
        if 'name' in input_data['metadata']['component']['manufacturer']:
            logging.info(f"смена названия организации {input_data['metadata']['component']['manufacturer']['name']} -> {args.manufacturer}")
            logging.info('-'*50)
        input_data['metadata']['component']['manufacturer']['name'] = args.manufacturer
    elif not 'name' in input_data['metadata']['component']['manufacturer']:
        input_data['metadata']['component']['manufacturer']['name'] = DEFAULT_VALUE

if args.ref or args.fix_all:
    nuget_addr = ''
    adapter = adapters.HTTPAdapter(max_retries=5)
    g = git.cmd.Git()
    purl_to_url = dict()
    stack = input_data.get('components', []).copy()
    with Session() as sess:
        sess.mount('http://', adapter=adapter)
        sess.mount('https://', adapter=adapter)
        while stack:
            component = stack.pop()
            if 'components' in component:
                stack += component['components']
            if 'purl' in component and not 'externalReferences' in component:
                if component['purl'] in purl_to_url:
                    if purl_to_url[component['purl']]:
                        component['externalReferences'] = [{'type':'vcs', 'url': purl_to_url[component['purl']]}]
                    continue
                logging.info(f'обработка purl {component["purl"]}')
                id, version = component['purl'].split("@")
                if id.startswith('pkg:nuget/'):
                    id = id[10:]
                    if not nuget_addr:
                        with sess.get("https://api.nuget.org/v3/index.json") as res:
                            for resource in res.json().get("resources", []):
                                if resource["@type"].startswith("PackageBaseAddress"):
                                    nuget_addr = resource["@id"]
                    package_address = f"{nuget_addr}{id.lower()}/{version.lower()}/{id.lower()}.nuspec"
                    root = []
                    with sess.get(package_address) as res:
                        root = ET.fromstring(res.text)
                    urls = []
                    for child in root:
                        if child.tag.endswith("metadata"):
                            for child2 in child:
                                if child2.tag.endswith("projectUrl"):
                                    if not child2.text in urls:
                                        urls.append(child2.text)
                                elif child2.tag.endswith("repository"):
                                    if child2.attrib.get("url", ''):
                                        if not child2.attrib['url'] in urls:
                                            urls.append(child2.attrib['url'])
                    urls = list(reversed(urls))
                elif id.startswith('pkg:gem/'):
                    id = id[8:]
                    gem_data = dict()
                    urls = []
                    kws = ['source_code_uri', 'project_uri', 'homepage_uri']
                    with sess.get(f'https://rubygems.org/api/v2/rubygems/{id.lower()}/versions/{version.lower()}.json') as res:
                        gem_data = res.json()
                    md = gem_data.get('metadata', dict())
                    for kw in kws:
                        url = gem_data.get(kw, '')
                        if url and not url in urls:
                            urls.append(url)
                        url = md.get(kw, '')
                        if url and not url in urls:
                            urls.append(url)
                else:
                    logging.info(f'неизвестный префикс purl {component["purl"]}')
                    logging.info('-'*50)
                    continue
                for url in urls:
                    if url.startswith('git://'):
                        url = "https" + url[3:]
                    try:
                        ls_res = g.ls_remote(url)
                        component['externalReferences'] = [{'type':'vcs', 'url': url}]
                        purl_to_url[component['purl']] = url
                        logging.info(f'присвоить url {url}')
                        break
                    except Exception as e:
                        continue
                else:
                    logging.info(f'ни одна из {urls} не является git-репозиторием')
                    purl_to_url[component['purl']] = None
                logging.info('-'*50)

if args.update:
    with open(args.update) as f:
        old_data = json.load(f)
    stack = old_data.get('components', [])
    old_data_dict = dict()
    while stack:
        component = stack.pop(0)
        old_data_dict[(component['name'], component['version'])] = dict()
        old_data_dict[(component['name'], component['version'])]['properties'] = component.get('properties', [])
        old_data_dict[(component['name'], component['version'])]['purl'] = component.get('purl', '')
        old_data_dict[(component['name'], component['version'])]['externalReferences'] = component.get('externalReferences', [])
        if 'components' in component:
            stack += component['components']

    stack = input_data.get('components', []).copy()
    while stack:
        component = stack.pop(0)
        key = (component['name'], component['version'])
        if key in old_data_dict:
            if any(old_data_dict[key].values()):
                logging.info(f"для компонента {component} присвоение полю")
            if old_data_dict[key]['properties']:
                logging.info(f"\"properties\" значения:\n{old_data_dict[key]['properties']}")
                component['properties'] = old_data_dict[key]['properties']
            if old_data_dict[key]['purl']:
                logging.info(f"\"purl\" значения:\n{old_data_dict[key]['purl']}")
                component['purl'] = old_data_dict[key]['purl']
            if old_data_dict[key]['externalReferences']:
                logging.info(f"\"externalReferences\" значения:\n{old_data_dict[key]['externalReferences']}")
                component['externalReferences'] = old_data_dict[key]['externalReferences']
            if any(old_data_dict[key].values()):
                logging.info('-'*50)
        if 'components' in component:
            stack += component['components']

    if 'metadata' in old_data and 'component' in old_data['metadata'] and 'name' in old_data['metadata']['component']:
        old_name = old_data['metadata']['component']['name']
        if not 'metadata' in input_data:
            input_data['metadata'] = dict()
        if not 'component' in input_data['metadata']:
            input_data['metadata']['component'] = dict()
        if not 'name' in input_data['metadata']['component']:
            logging.info(f"перенос названия продукта: {old_name}")
            logging.info('-'*50)
            input_data['metadata']['component']['name'] = old_name
    if 'metadata' in old_data and 'component' in old_data['metadata'] and 'version' in old_data['metadata']['component']:
        old_version = old_data['metadata']['component']['version']
        if not 'metadata' in input_data:
            input_data['metadata'] = dict()
        if not 'component' in input_data['metadata']:
            input_data['metadata']['component'] = dict()
        if not 'version' in input_data['metadata']['component']:
            logging.info(f"перенос версии продукта: {old_version}")
            logging.info('-'*50)
            input_data['metadata']['component']['version'] = old_version
    if 'metadata' in old_data and 'component' in old_data['metadata'] and 'manufacturer' in old_data['metadata']['component'] and \
        'name' in old_data['metadata']['component']['manufacturer']:
        old_manufacturer = old_data['metadata']['component']['manufacturer']['name']
        if not 'metadata' in input_data:
            input_data['metadata'] = dict()
        if not 'component' in input_data['metadata']:
            input_data['metadata']['component'] = dict()
        if not 'manufacturer' in input_data['metadata']['component']:
            input_data['metadata']['component']['manufacturer'] = dict()
        if not 'name' in input_data['metadata']['component']['manufacturer']:
            logging.info(f"перенос названия организации: {old_manufacturer}")
            logging.info('-'*50)
            input_data['metadata']['component']['manufacturer']['name'] = old_manufacturer

if 'metadata' in input_data:
    input_data['metadata']['timestamp'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
if 'version' in input_data:
    input_data['version'] += 1
with open(args.output, 'w') as f:
    json.dump(input_data, f, indent=2)