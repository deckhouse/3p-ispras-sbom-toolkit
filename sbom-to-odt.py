# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import argparse
import json

from odf.opendocument import load
from odf.table import Table, TableRow, TableCell
from odf.text import P

def get_prop(arr, name):
    for elem in arr:
        if elem.get('name', '') == name:
            return elem.get('value', '')
    return ''

parser = argparse.ArgumentParser(description='генератор таблицы компонентов в формате odt')
parser.add_argument('input', help='входной файл, содержащий перечень заимствованных компонентов, в JSON формате')
parser.add_argument('output', help='выходной файл в формате odt, содержащий таблицу со всеми компонентами из входного файла')

args = parser.parse_args()
with open(args.input, 'r', encoding='utf-8') as f:
    input_data = json.load(f)

doc = load('./template.odt')
stack = input_data.get('components', []).copy()
idx = 1
added_elements = set()
for item in doc.getElementsByType(Table):
    while stack:
        comp = stack.pop(0)
        if 'components' in comp:
            stack += comp['components']
        element = (comp.get('name', ''),
                   comp.get('version', ''),
                   get_prop(comp.get('properties', []), 'source_langs'),
                   get_prop(comp.get('properties', []), 'GOST:attack_surface'),
                   get_prop(comp.get('properties', []), 'GOST:security_function'),
                   comp.get('externalReferences', [{'url':''}])[0].get('url', ''))
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

doc.save(args.output)