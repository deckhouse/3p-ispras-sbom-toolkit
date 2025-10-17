# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import concurrent.futures
import json
import jsonschema
import logging
from pathlib import Path
import re
from referencing import Registry, Resource

from sbom_utils import check_repo, opener, parse_repo_url, load_cache, dump_cache, is_archive_url, get_prop

parser = argparse.ArgumentParser(description='проверка sbom-файлов')
parser.add_argument('filename', help='входной файл в формате CycloneDX JSON для проверки')
parser.add_argument('-e', '--errors', type=int, default=10,
                    help='максимальное число ошибок для вывода; по умолчанию 10; установите 0 для вывода всех ошибок')
parser.add_argument('--check-vcs', action='store_true', help='проверка url типа vcs на git/svn/hg/fossil-репозиторий (требуется доступ к Интернет и наличие пакетов git, subversion и mercurial)')
parser.add_argument('--check-vcs-leaf-only', action='store_true', help='то же, что и --check-vcs, но проверяются только url в листовых компонентах')
parser.add_argument('--check-source-distribution', action='store_true', help='проверка существования URL для типа source-distribution и проверка того, что по указанной URL находится архив')
parser.add_argument('--format', type=str, default='oss',
                    help='--format=oss для проверки файла-перечня заимствованных программных компонентов с открытым исходным кодом; --format=container для проверки файла-перечня образов контейнеров; по умолчанию oss')
parser.add_argument('-v', '--verbose', action='store_true', help='подробный вывод')


registry = None
with open(Path(__file__).parent.resolve() / 'additional_schemas' / "spdx.schema.json") as f:
    resource1 = Resource.from_contents(json.load(f))
with open(Path(__file__).parent.resolve() / 'additional_schemas' / "jsf-0.82.schema.json") as f:
    resource2 = Resource.from_contents(json.load(f))
registry = Registry().with_resources(
    [
        ("spdx.schema.json", resource1),
        ("jsf-0.82.schema.json", resource2),
    ],
)

args = parser.parse_args()
if args.verbose:
    logging.basicConfig(format='%(message)s', level="INFO")

# encoding and duplicate keys detection
data, encoding = opener(args.filename, pairs=True)

with open(args.filename, encoding=encoding) as f:
    parsed_file = json.load(f)
try:
    with open(Path(__file__).parent.resolve() / 'schemas' / ('schema_container.json' if args.format == 'container' else 'schema.json')) as f:
        schema = json.load(f)
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    if registry:
        validator = cls(schema, format_checker=cls.FORMAT_CHECKER, registry=registry)
    else:
        validator = cls(schema, format_checker=cls.FORMAT_CHECKER)
    errors = validator.iter_errors(parsed_file)
    count = 0
    limit = args.errors
    for err in errors:
        count += 1
        if err.message.endswith(' has non-unique elements'):
            p = re.compile('(?<!\\\\)\'')
            arr = err.instance
            dups = []
            for n, i in enumerate(arr):
                if i in arr[n+1:] and not i in dups:
                    dups.append(i)
            inst = ''
            for line in str(err).split('\n'):
                if line.startswith('On instance'):
                    inst = line[:-1]
                    break
            print(f'ERROR: {inst} non-unique elements:\n' + '\n'.join([str(x) for x in dups]))
        elif err.message.startswith('Additional properties are not allowed'):
            print(f'ERROR: {err.message}\n\nOn {jsonschema.exceptions._pretty(err.instance, 16 * " ")}')
        else:
            print("ERROR: " + str(err))
        print('-'*50)
        if limit and count == limit:
            break
    if args.format == 'container':
        values = {'yes': 2, 'indirect': 1, 'no': 0}
        for container in parsed_file.get('components', []):
            attack_surface = get_prop(container.get('properties', []), 'GOST:attack_surface')
            security_function = get_prop(container.get('properties', []), 'GOST:security_function')
            stack = container.get('components', []).copy()
            eq_as = eq_sf = False
            while stack:
                component = stack.pop(0)
                components_value = component.get('components', [])
                if components_value:
                    stack += components_value
                component_attack_surface = get_prop(component.get('properties', []), 'GOST:attack_surface')
                component_security_function = get_prop(component.get('properties', []), 'GOST:security_function')
                if values[component_attack_surface] > values[attack_surface]:
                    count += 1
                    print(f"ERROR: контейнер \"{container['name']}\" сожержит компонент \"{component['name']}\" с бóльшим значением поверхности атаки ({component_attack_surface} > {attack_surface})")
                    print('-'*50)
                elif not eq_as and values[component_attack_surface] == values[attack_surface]:
                    eq_as = True
                if limit and count >= limit:
                    break
                if values[component_security_function] > values[security_function]:
                    count += 1
                    print(f"ERROR: контейнер \"{container['name']}\" сожержит компонент \"{component['name']}\" с бóльшим значением функции безопасности ({component_security_function} > {security_function})")
                    print('-'*50)
                elif not eq_sf and values[component_security_function] == values[security_function]:
                    eq_sf = True
                if limit and count >= limit:
                    break
            else:
                if not eq_as:
                    count += 1
                    print(f"ERROR: контейнер \"{container['name']}\" не сожержит компонентов со значением его поверхности атаки ({security_function})")
                    print('-'*50)
                if limit and count >= limit:
                    break
                if not eq_sf:
                    count += 1
                    print(f"ERROR: контейнер \"{container['name']}\" не сожержит компонентов со значением его функции безопасности ({security_function})")
                    print('-'*50)
                if limit and count >= limit:
                    break
                continue
            break
    if args.check_vcs or args.check_vcs_leaf_only or args.check_source_distribution:
        import os
        os.environ['GIT_TERMINAL_PROMPT'] = '0'
        stack = parsed_file.get('components', []).copy()
        not_repos = 0
        repo_dict = load_cache('vcs')
        src_list = set()
        src_results = load_cache('source-distribution')
        not_arch_url = 0
        refs_to_check = dict()
        while stack:
            component = stack.pop(0)
            components_value = component.get('components', [])
            if components_value:
                stack += components_value
            if args.check_vcs_leaf_only and components_value:
                continue
            refs = component.get('externalReferences', [])
            if type(refs) == list:
                for ref in refs:
                    if type(ref) == dict and ref.get('type', '') == 'vcs':
                        url = ref.get('url', '')
                        res = parse_repo_url(url)
                        if res and res[1]:
                            url = res[0]
                        ex_str = ''
                        if not url in repo_dict:
                            if not url in refs_to_check:
                                refs_to_check[url] = set()
                            refs_to_check[url].add(ref.get('url', ''))
                    if args.check_source_distribution:
                        if type(ref) == dict and ref.get('type', '') == 'source-distribution':
                            url = ref.get('url', '')
                            if not url in src_results:
                                src_list.add(url)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_url = {executor.submit(check_repo, url): ('vcs', url) for url in refs_to_check.keys()}
            future_to_url.update({executor.submit(is_archive_url, url): ('source-distribution', url) for url in src_list})
            for future in concurrent.futures.as_completed(future_to_url):
                type, url = future_to_url[future]
                try:
                    if type == 'vcs':
                        repo_dict[url], ex_str = future.result()
                    elif type == 'source-distribution':
                        src_results[url], ex_str = future.result()
                except Exception as exc:
                    print('ERROR: %r generated an exception: %s' % (url, exc))
                else:
                    if type == 'vcs' and not repo_dict[url]:
                        not_repos += len(refs_to_check[url])
                        for u in sorted(list(refs_to_check[url])):
                            logging.info(ex_str)
                            print(f"WARNING: {u} не подходит под шаблон и не является git/svn/hg/fossil-репозиторием")
                            print('-'*50)
                    if type == 'source-distribution' and not src_results[url]:
                        not_arch_url += 1
                        logging.info(ex_str)
                        print(f"WARNING: {url} не указывает на архив или не существует")
                        print('-'*50)
        dump_cache('vcs', {k:v for k,v in repo_dict.items() if v})
        dump_cache('source-distribution', {k:v for k,v in src_results.items() if v})
        if not_repos == 0 and count == 0 and not_arch_url == 0:
            print('файл корректный')
    elif count == 0:
        print('файл корректный')
except jsonschema.exceptions.SchemaError as se:
    print('ошибка в файле-спецификации:')
    print(se)
