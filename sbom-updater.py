# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import datetime
import json
import logging
import os
from pathlib import Path
from requests import Session, adapters
import xml.etree.ElementTree as ET

from sbom_utils import opener, check_repo, load_cache, dump_cache

DEFAULT_VALUE = "TODO"

def has_prop(arr, name):
    for elem in arr:
        if elem.get('name', '') == name:
            return True
    return False

def get_website(ref_arr):
    for elem in ref_arr:
        if elem['type'] == 'website':
            return elem
    return False

class RefFinder(object):
    def __init__(self, purl_file=None):
        self._placeholder_url = 'sbom-updater_generated_placeholder:'
        self._nuget_addr = None
        self._session = Session()
        adapter = adapters.HTTPAdapter(max_retries=5)
        self._session.mount('http://', adapter=adapter)
        self._session.mount('https://', adapter=adapter)
        self._prefixes = {
            'pkg:nuget/': self._nuget_purl,
            'pkg:gem/': self._gem_purl,
        }
        self._purl_to_url = dict()
        try:
            with open(purl_file) as f:
                self._purl_to_url = json.load(f)
        except Exception:
            pass
        self._repo_dict = load_cache()
        os.environ['GIT_TERMINAL_PROMPT'] = '0'

    def is_repo(self, url):
        if not url in self._repo_dict:
            self._repo_dict[url], ex_str = check_repo(url)
            if not self._repo_dict[url]:
                logging.info(ex_str)
        return self._repo_dict[url]

    def dump_repos(self):
        dump_cache({k:v for k,v in self._repo_dict.items() if v})

    def process_purl(self, purl):
        if purl in self._purl_to_url:
            return self._purl_to_url[purl]
        logging.info(f'обработка purl {purl}')

        urls = self._ecosystems(purl)
        url = self._analyse_urls(urls, purl, 'ecosyste.ms: ')
        if not url:
            for k, f in self._prefixes.items():
                if purl.startswith(k):
                    urls = f(purl)
                    url = self._analyse_urls(urls, purl, '')
                    break
            else:
                logging.info(f'не удалось найти репозиторий для purl {purl}')
        logging.info('-'*50)
        self._purl_to_url[purl] = url if url else self._placeholder_url
        return self._purl_to_url[purl]

    def _analyse_urls(self, urls, purl, log_prefix):
        for url in urls:
            if type(url) == str:
                if url.startswith('git://'):
                    url = "https" + url[3:]
                if self.is_repo(url):
                    logging.info(f'{log_prefix}найден репозиторий {url} среди {urls}')
                    return url
        logging.info(f'{log_prefix}ни одна из {urls} не является git-репозиторием')
        return None

    def _ecosystems(self, purl):
        ecosystems_data = None
        with self._session.get(f"https://packages.ecosyste.ms/api/v1/packages/lookup?purl={purl.lower()}") as res:
            ecosystems_data = res.json()
        if ecosystems_data:
            ecosystems_data = ecosystems_data[0]
            return [ecosystems_data.get("repository_url", ''), ecosystems_data.get("registry_url", ''), ecosystems_data.get("homepage", '')]
        return []

    def _nuget_purl(self, purl):
        id, version = purl.split("@")
        id = id[10:]
        if not self._nuget_addr:
            with self._session.get("https://api.nuget.org/v3/index.json") as res:
                for resource in res.json().get("resources", []):
                    if resource["@type"].startswith("PackageBaseAddress"):
                        self._nuget_addr = resource["@id"]
        package_address = f"{self._nuget_addr}{id.lower()}/{version.lower()}/{id.lower()}.nuspec"
        root = []
        with self._session.get(package_address) as res:
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
        return list(reversed(urls))

    def _gem_purl(self, purl):
        id, version = purl.split("@")
        id = id[8:]
        gem_data = dict()
        urls = []
        kws = ['source_code_uri', 'project_uri', 'homepage_uri']
        with self._session.get(f'https://rubygems.org/api/v2/rubygems/{id.lower()}/versions/{version.lower()}.json') as res:
            gem_data = res.json()
        md = gem_data.get('metadata', dict())
        for kw in kws:
            url = gem_data.get(kw, '')
            if url and not url in urls:
                urls.append(url)
            url = md.get(kw, '')
            if url and not url in urls:
                urls.append(url)
        return urls


parser = argparse.ArgumentParser(description='изменение sbom-файлов')
parser.add_argument('input', help='входной файл в формате CycloneDX JSON, содержащий актуальную информацию о составе заимствованных компонентов')
parser.add_argument('output', help='выходной файл с дооформленным переченем заимствованных компонентов')
parser.add_argument('--props', action='store_true',
                    help='добавить {"name": "GOST:attack_surface", "value": "yes"} и {"name": "GOST:security_function", "value": "yes"} в поле "properties" для каждого компонента входного файла, при их отсутствии')
parser.add_argument('--app-name', help='установить название продукта')
parser.add_argument('--app-version', help='установить версию продукта')
parser.add_argument('--manufacturer', help='установить название организации — изготовителя продукта')
parser.add_argument('--ref', action='store_true', help='установить поле "externalReferences", основываясь на поле "purl" компонента; если ссылки на репозиторий не было найдено, используется "sbom-updater_generated_placeholder:"')
parser.add_argument('--fix-all', action='store_true', help=f'применить все вышеописанные опции; если необходимое поле остутствует и его значение не указано, используется "{DEFAULT_VALUE}"')
parser.add_argument('--update', metavar='OLD_SBOM', help='предыдущая версия перечня заимствованных компонентов, состав и версии которых могли устареть, но метаинформацию о приложении и компонентах требуется по возможности перенести в новый перечень')
parser.add_argument('-v', '--verbose', action='store_true', help='подробный вывод')

args = parser.parse_args()
if args.verbose:
    logging.basicConfig(format='%(message)s', level="INFO")
input_data, encoding = opener(args.input)

if args.fix_all:
    if input_data['specVersion'] != '1.6':
        logging.info(f"смена 'specVersion' с {input_data['specVersion']} на 1.6")
        logging.info('-'*50)
        input_data['specVersion'] = '1.6'

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
    ref_finder = RefFinder(Path(__file__).parent.resolve() / 'purl_to_vcs.json')
    stack = input_data.get('components', []).copy()
    while stack:
        component = stack.pop(0)
        if 'components' in component:
            stack += component['components']
        if 'purl' in component and not 'externalReferences' in component:
            url = ref_finder.process_purl(component['purl'])
            if url:
                component['externalReferences'] = [{'type':'vcs', 'url': url}]
        website_ref = get_website(component.get('externalReferences', []))
        if website_ref and ref_finder.is_repo(website_ref['url']):
            website_ref['type'] = 'vcs'
            logging.info(f"смена типа с 'website' на 'vcs' для {website_ref['url']}")
            logging.info('-'*50)
    ref_finder.dump_repos()

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
with open(args.output, 'w', encoding=encoding) as f:
    json.dump(input_data, f, indent=2, ensure_ascii=False)