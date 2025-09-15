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
import subprocess
import gostcrypto

from sbom_utils import opener, check_repo, load_cache, dump_cache, is_archive_url

DEFAULT_VALUE = "TODO"
DEFAULT_VCS_FILE_NAME = 'purl_to_vcs.json'
DEFAULT_VCS_FILE_PATH = Path(__file__).parent.resolve() / DEFAULT_VCS_FILE_NAME
DEFAULT_DELETE_FILE_NAME = 'purl_to_delete.json'
DEFAULT_DELETE_FILE_PATH = Path(__file__).parent.resolve() / DEFAULT_DELETE_FILE_NAME
DEFAULT_PROPS_VALUE = 'yes'
DEFAULT_PROPS_LANGS = 'source_langs'
PROPS_VALUES = ['yes', "indirect", "no"]
DEFAULT_PROPS_FILE_NAME = 'purl_to_props.json'
DEFAULT_PROPS_FILE_PATH = Path(__file__).parent.resolve() /  DEFAULT_PROPS_FILE_NAME
HASH_ALGS = {'streebog256': 'STREEBOG-256', 'streebog512': 'STREEBOG-512'}

def has_prop(arr, name, value=False):
    for elem in arr:
        if elem.get('name', '') == name:
            return True if not value else elem.get('value', None)
    return False

def get_website(ref_arr):
    for elem in ref_arr:
        if elem['type'] == 'website':
            return elem
    return False

def delete_components(components, delete_list):
    for component in reversed(components):
        if any(component["purl"].startswith(prefix) for prefix in delete_list):
            components.remove(component)
        else:
            nested_components = component.get("components", False)
            if nested_components:
                delete_components(nested_components, delete_list)

class RefFinder(object):
    def __init__(self, purl_file=None, hash_algorithm=False):
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
        self._repo_dict = load_cache('vcs')
        self._archive_dict = load_cache('archives')
        
        self._language_map = {"ansic": "C", "cs": "C#", "cpp": "C++", "objc": "Objective-C"}
        self._language_exclude = ["yacc", "makefile", "lex", "asm", "xml", "awk", "tcl", "sed", "asm", "exp", "ada", "csh", "lisp", "f90", "mi"]
        self._hash_algorithm = hash_algorithm
        os.environ['GIT_TERMINAL_PROMPT'] = '0'

    def is_repo(self, url):
        if not url in self._repo_dict:
            self._repo_dict[url], ex_str = check_repo(url)
            if not self._repo_dict[url]:
                logging.info(ex_str)
        return self._repo_dict[url]
    
    def is_archive(self,url):
        if url not in self._archive_dict:
            self._archive_dict[url], ex_str = is_archive_url(url)
            if not self._archive_dict[url]:
                logging.info(ex_str)
        return self._archive_dict[url]

    def download_and_hash(self, url, algorithm='streebog256'):
        buffer_size = 128
        hash_obj = gostcrypto.gosthash.new(algorithm)
        with self._session.get(url, stream=True) as res:
            res.raise_for_status()
            for chunk in res.iter_content(buffer_size):
                if chunk:
                    hash_obj.update(chunk)
        hash_result = hash_obj.hexdigest()
        return(hash_result)

    def dump_repos(self):
        dump_cache('vcs', {k:v for k,v in self._repo_dict.items() if v})

    def process_purl(self, component, use_apt=False):
        url = language = None
        
        if component['purl'] in self._purl_to_url:
            url = self._purl_to_url[component['purl']]
        language = has_prop(component['properties'], DEFAULT_PROPS_LANGS, value=True) 
        
        if not url or not language:
            if component['purl'].startswith('pkg:deb/'):
                urls, lang = self._debian(component, use_apt if not url else False)
            else:
                urls, lang = self._ecosystems(component['purl'])
        else:
            return url, language
        if not url:
            url = self._analyse_urls(urls, component['purl'], 'debian: ' if component['purl'].startswith('pkg:deb/') else 'ecosyste.ms: ')
        if not url:
            for k, f in self._prefixes.items():
                if component['purl'].startswith(k):
                    urls, lang = f(component['purl'])
                    url = self._analyse_urls(urls, component['purl'], '')
                    break
            else:
                logging.info(f'не удалось найти репозиторий для purl {component["purl"]}')
        
        if not language:
            language = lang
        logging.info('-'*50)
        self._purl_to_url[component['purl']] = url if url else self._placeholder_url
        return self._purl_to_url[component['purl']], language

    def _analyse_urls(self, urls, purl, log_prefix):
        file_urls=[]
        for url in urls:
            if type(url) == str:
                if url.startswith('git://'):
                    url = "https" + url[3:]
                if self.is_repo(url):
                    logging.info(f'{log_prefix}найден репозиторий {url} среди {urls}')
                    return url
                elif self.is_archive(url):
                    logging.info(f'{log_prefix}найден архив {url} среди {urls}')
                    file_urls.append(url)
        if file_urls:
            file_links = []
            for file in file_urls:
                file_links.append({'type': "source-distribution", "url": file, "hashes": [{"alg": HASH_ALGS.get(self._hash_algorithm, DEFAULT_VALUE) if self._hash_algorithm else DEFAULT_VALUE, "content": self.download_and_hash(url=file, algorithm=self._hash_algorithm)} if self._hash_algorithm else DEFAULT_VALUE]})
            return file_links
        
        logging.info(f'{log_prefix}ни одна из {urls} не является git-репозиторием или архивом')
        return None

    def _debian(self, component, use_apt=False):
        source = pkg_name = component['name']
        source_version = pkg_version = component['version']

        if 'properties' in component:
            if has_prop(component['properties'], 'source'):
                source = has_prop(component['properties'], 'source', value=True)
                if ' ' in source:
                    source, source_version = source.split(' ')
                    source_version = source_version.strip('()')
        try: 
            res = self._session.get(f"https://sources.debian.org/api/src/{source}/{source_version}/")
            if res.status_code == 200 and not res.json().get('pkg_infos', {}).get('vcs_browser' , False):
                res = self._session.get(f"https://sources.debian.org/api/src/{source}/latest/")
            if res.status_code != 200:
                debian_data={}
            else:
                debian_data = res.json()
        except Exception as ex:
            debian_data={}
            logging.info(f"Получение данных от sources.debian.org для {component['purl'].lower()} завершилось с ошибкой {ex}")

        lang_list=[]
        for lang in debian_data.get('pkg_infos', {}).get('sloc', []):
            if lang[0].lower() in self._language_exclude:
                break
            lang_list.append(self._language_map.get(lang[0].lower(), lang[0]).capitalize())
        language = ", ".join(lang_list)
        
        url = [debian_data.get('pkg_infos', {}).get('vcs_browser', False)]
        
        if use_apt and not self.is_repo(url[0]):
            deban_source_urls = []
            try:
                res = subprocess.run(f"apt source -qqq --print-uris '{pkg_name}={pkg_version}' | awk '{{print $1}}'", shell=True, capture_output=True, text=True, timeout=60)
                if res.returncode == 0:
                    for line in [line for line in res.stdout.split("\n") if line]:
                        file = line.replace("'", '')
                        deban_source_urls.append(file)
                if deban_source_urls:
                    url = deban_source_urls
            except Exception as ex:
                logging.info(f"Получение данных с помощью apt source для {component['purl'].lower()} завершилось с ошибкой {ex}")   
        return url if url else self._placeholder_url , language
            
    def _ecosystems(self, purl):
        ecosystems_data = None
        try:
            with self._session.get(f"https://packages.ecosyste.ms/api/v1/packages/lookup?purl={purl.lower()}") as res:
                ecosystems_data = res.json()
            if ecosystems_data:
                ecosystems_data = ecosystems_data[0]
                return [ecosystems_data.get("repository_url", ''), ecosystems_data.get("registry_url", ''), ecosystems_data.get("homepage", '')], ecosystems_data.get('repo_metadata', {}).get('language', '')
        except Exception as ex:
            logging.info(f"Получение данных с помощью ecosystems для {component['purl'].lower()} завершилось с ошибкой {ex}")
        return [] , ''

    def _nuget_purl(self, purl):
        id, version = purl.split("@") if '@' in purl else (purl, '')
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
        return list(reversed(urls)), ""

    def _gem_purl(self, purl):
        id, version = purl.split("@") if '@' in purl else (purl, '')
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
        return urls, "Ruby"


parser = argparse.ArgumentParser(description='изменение sbom-файлов')
parser.add_argument('input', help='входной файл в формате CycloneDX JSON, содержащий актуальную информацию о составе заимствованных компонентов')
parser.add_argument('output', help='выходной файл с дооформленным переченем заимствованных компонентов')
parser.add_argument('--props', default=False, nargs='?', const=PROPS_VALUES[0], choices=PROPS_VALUES,
                    help=f'установить значения для {{"name": "GOST:attack_surface", "value": "{"/".join(PROPS_VALUES)}"}} и {{"name": "GOST:security_function", "value": "yes/indirect/no"}}, в поле "properties" для каждого компонента входного файла, при отсутствии у компонента; По умолчанию "{PROPS_VALUES[0]}"')
parser.add_argument('--props-file', default=DEFAULT_PROPS_FILE_PATH, nargs='?', const=DEFAULT_PROPS_FILE_PATH, type=str, help=f'добавить в поле "properties" компонента, основываясь на поле "purl" компонента из указанного файла; По умолчанию ./{DEFAULT_PROPS_FILE_NAME}')
parser.add_argument('--app-name', help='установить название продукта')
parser.add_argument('--app-version', help='установить версию продукта')
parser.add_argument('--manufacturer', help='установить название организации — изготовителя продукта')
parser.add_argument('--type', help='установить тип продукта')
parser.add_argument('--ref', action='store_true', help='установить поле "externalReferences", основываясь на поле "purl" компонента; если ссылки на репозиторий не было найдено, используется "sbom-updater_generated_placeholder:"')
parser.add_argument('--ref-file', default=DEFAULT_VCS_FILE_PATH, type=str, help=f'путь до файла используемого для заполнения поля "externalReferences"; По умолчанию ./{DEFAULT_VCS_FILE_NAME}')
parser.add_argument('--use-apt', action='store_true', help='использовать apt source для получения ссылок на архивы с исходными кодами для компонентов pkg:deb при невозможности получить ссылку на vcs')
parser.add_argument('--hasher', default=False, nargs='?', const=list(HASH_ALGS.keys())[0], choices=list(HASH_ALGS.keys()), help=f'указать алгоритм для получения хеш-суммы, если "externalReferences" является ссылкой на архив; по умолчанию {list(HASH_ALGS.keys())[0]}')
parser.add_argument('--delete', default=False, nargs='?', const=DEFAULT_DELETE_FILE_PATH, type=str, help=f'Удалить компоненты на основе "purl" указанные в файле; По умолчанию ./{DEFAULT_DELETE_FILE_NAME}')
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

if args.delete or args.fix_all:
    if not args.delete:
        args.delete=DEFAULT_DELETE_FILE_PATH
    purl_to_delete = list()
    try:
        with open(args.delete) as f:
            purl_to_delete = json.load(f)
    except Exception:
        pass
    delete_components(input_data.get('components', []), purl_to_delete)

if args.props or args.fix_all:
    if not args.props:
        args.props = DEFAULT_PROPS_VALUE
    purl_to_props = dict()
    try:
        with open(args.props_file) as f:
            purl_to_props = json.load(f)
    except Exception:
        pass
    stack = input_data.get('components', []).copy()
    while stack:
        component = stack.pop()
        if not 'properties' in component:
            component['properties'] = []
        
        for name, value in purl_to_props.get(component['purl'], {}).items():
            if not has_prop(component['properties'], name):
                component['properties'].append({'name': name, 'value': value})
        if not has_prop(component['properties'], 'GOST:attack_surface'):
            component['properties'].append({'name': 'GOST:attack_surface', 'value': args.props if args.props else DEFAULT_PROPS_VALUE})
        if not has_prop(component['properties'], 'GOST:security_function'):
            component['properties'].append({'name': 'GOST:security_function', 'value': args.props if args.props else DEFAULT_PROPS_VALUE})
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

if not args.type is None or args.fix_all:
    if not 'metadata' in input_data:
        input_data['metadata'] = dict()
    if not 'component' in input_data['metadata']:
        input_data['metadata']['component'] = dict()
    if not 'type' in input_data['metadata']['component']:
        input_data['metadata']['component']['type'] = dict()
    if not args.type is None:
        if 'type' in input_data['metadata']['component']['type']:
            logging.info(f"смена типа компонента {input_data['metadata']['component']['type']} -> {args.type}")
            logging.info('-'*50)
        input_data['metadata']['component']['type'] = args.type
    elif not 'type' in input_data['metadata']['component']['type']:
        input_data['metadata']['component']['type'] = DEFAULT_VALUE

if args.ref or args.fix_all:
    ref_finder = RefFinder(args.ref_file, hash_algorithm=args.hasher if args.hasher else list(HASH_ALGS.keys())[0] if args.fix_all else False)
    stack = input_data.get('components', []).copy()
    while stack:
        component = stack.pop(0)
        if 'components' in component:
            stack += component['components']
        if 'purl' in component and not 'externalReferences' in component:
            url, language = ref_finder.process_purl(component, args.fix_all if args.fix_all else args.use_apt)
            if isinstance(url, list):
                component['externalReferences'] = url
            elif url:
                component['externalReferences'] = [{'type':'vcs', 'url': url}]
            if language:
                component['properties'].append({"name": DEFAULT_PROPS_LANGS, "value": language})
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
