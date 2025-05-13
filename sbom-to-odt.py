# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
from odf.opendocument import load
from odf.table import Table, TableRow, TableCell
from odf.text import P
from odf.style import TextProperties
from pathlib import Path

from sbom_utils import opener

def get_prop(arr, name):
    for elem in arr:
        if elem.get('name', '') == name:
            return elem.get('value', '')
    return ''

def get_ext_ref(er_list):
    for er in er_list:
        if er['type'] in ['vcs', 'source-distribution']:
            return er['url']
    return ''

parser = argparse.ArgumentParser(description='генератор таблицы компонентов в формате odt')
parser.add_argument('input', help='входной файл, содержащий перечень заимствованных компонентов, в JSON формате')
parser.add_argument('output', help='выходной файл в формате odt, содержащий таблицу со всеми компонентами из входного файла')
parser.add_argument('-t', '--pa-fb-ontop', action='store_true', help='помещение записей "ПА" и "ФБ" в топ таблицы')
parser.add_argument('--format', type=str, default='oss',
                    help='--format=oss если входной файл — перечень заимствованных программных компонентов с открытым исходным кодом; --format=container если входной файл — перечень образов контейнеров; по умолчанию oss')

args = parser.parse_args()
input_data, encoding = opener(args.input)

idx = 1
added_elements = set()
components = list()
if args.format == 'oss':
    doc = load(Path(__file__).parent.resolve() / 'odt_templates' / 'template.odt')
    stack = input_data.get('components', []).copy()
    for item in doc.getElementsByType(Table):
        while stack:
            comp = stack.pop(0)
            if 'components' in comp:
                stack += comp['components']
            components.append(comp)
        if args.pa_fb_ontop:
            components = sorted(components,\
                                key=lambda x: (get_prop(x.get('properties', []), 'GOST:attack_surface') in {'yes', 'indirect'},\
                                            get_prop(x.get('properties', []), 'GOST:security_function') in {'yes', 'indirect'}),\
                                            reverse=True)
        while components:
            comp = components.pop(0)
            element = (comp.get('name', ''),
                    comp.get('version', ''),
                    get_prop(comp.get('properties', []), 'source_langs'),
                    get_prop(comp.get('properties', []), 'GOST:attack_surface'),
                    get_prop(comp.get('properties', []), 'GOST:security_function'),
                    get_ext_ref(comp.get('externalReferences', [])))
            if element in added_elements:
                continue
            added_elements.add(element)
            tr = TableRow(stylename='Table3.1')
            tc = TableCell(stylename='Table3.A1')
            tc.addElement(P(text=str(idx), stylename='P3'))
            tr.addElement(tc)
            tc = TableCell(stylename='Table3.A1')
            tc.addElement(P(text=element[0], stylename='P3'))
            tr.addElement(tc)
            tc = TableCell(stylename='Table3.A1')
            tc.addElement(P(text=element[1], stylename='P3'))
            tr.addElement(tc)
            tc = TableCell(stylename='Table3.A1')
            tc.addElement(P(text=element[2], stylename='P3'))
            tr.addElement(tc)
            _as_text = ''
            _as = element[3]
            if _as == 'yes':
                _as_text = 'поверхность атаки'
            elif _as == 'indirect':
                _as_text = 'косвенная поверхность атаки'
            _sf_text = ''
            _sf = element[4]
            if _sf == 'yes':
                _sf_text = 'функция безопасности'
            elif _sf == 'indirect':
                _sf_text = 'поддерживающая функции безопасности'
            tc = TableCell(stylename='Table3.A1')
            tc.addElement(P(text=(', '.join([_as_text, _sf_text]) if _as_text and _sf_text else (_as_text+_sf_text)), stylename='P3'))
            tr.addElement(tc)
            tc = TableCell(stylename='Table3.A1')
            tc.addElement(P(text=element[5], stylename='P3'))
            tr.addElement(tc)
            item.addElement(tr)
            idx += 1
else:
    doc = load(Path(__file__).parent.resolve() / 'odt_templates' / 'template_container.odt')
    for item in doc.getElementsByType(Table):
        st = doc.getStyleByName('P4')
        st.addElement(TextProperties(attributes={'fontsize':"10pt"}))
        components = input_data.get('components', []).copy()
        if args.pa_fb_ontop:
            components = sorted(components,\
                                key=lambda x: (get_prop(x.get('properties', []), 'GOST:attack_surface') in {'yes', 'indirect'},\
                                            get_prop(x.get('properties', []), 'GOST:security_function') in {'yes', 'indirect'}),\
                                            reverse=True)
        for comp in components:
            stack = comp.get('components', []).copy()
            deps = []
            while stack:
                dep = stack.pop(0)
                if 'components' in dep:
                    stack += dep['components']
                value = dep.get('name', '') + ' ' + dep.get('version', '')
                if not value in deps:
                    deps.append(value)
            element = (comp.get('name', ''),
                       comp.get('description', ''),
                    get_prop(comp.get('properties', []), 'GOST:attack_surface'),
                    get_prop(comp.get('properties', []), 'GOST:security_function'))
            tr = TableRow(stylename='Table2')
            tc = TableCell(stylename='Table2.A1')
            tc.addElement(P(text=str(idx), stylename=st))
            tr.addElement(tc)
            tc = TableCell(stylename='Table2.A1')
            tc.addElement(P(text=element[0], stylename=st))
            tr.addElement(tc)
            tc = TableCell(stylename='Table2.A1')
            tc.addElement(P(text=element[1], stylename=st))
            tr.addElement(tc)
            tc = TableCell(stylename='Table2.A1')
            tc.addElement(P(text='\n'.join(deps), stylename=st))
            tr.addElement(tc)
            _as_text = ''
            _as = element[2]
            if _as == 'yes':
                _as_text = 'поверхность атаки'
            elif _as == 'indirect':
                _as_text = 'косвенная поверхность атаки'
            _sf_text = ''
            _sf = element[3]
            if _sf == 'yes':
                _sf_text = 'функция безопасности'
            elif _sf == 'indirect':
                _sf_text = 'поддерживающая функции безопасности'
            tc = TableCell(stylename='Table2.A1')
            tc.addElement(P(text=(', '.join([_as_text, _sf_text]) if _as_text and _sf_text else (_as_text+_sf_text)), stylename=st))
            tr.addElement(tc)
            item.addElement(tr)
            idx += 1

doc.save(args.output)