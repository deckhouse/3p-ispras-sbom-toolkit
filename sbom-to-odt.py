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

parser = argparse.ArgumentParser(description='sbom to odt converter')
parser.add_argument('input', help='sbom file')
parser.add_argument('output', help='odt file')

args = parser.parse_args()
with open(args.input, 'r') as f:
    input_data = json.load(f)

doc = load('./template.odt')
for item in doc.getElementsByType(Table):
    for idx, comp in enumerate(input_data.get('components', [])):
        tr = TableRow(stylename='Table3.1')
        tc = TableCell(stylename='Table3.A1')
        tc.addElement(P(text=str(idx+1), stylename='P3'))
        tr.addElement(tc)
        tc = TableCell(stylename='Table3.A1')
        tc.addElement(P(text=comp.get('name', ''), stylename='P3'))
        tr.addElement(tc)
        tc = TableCell(stylename='Table3.A1')
        tc.addElement(P(text=comp.get('version', ''), stylename='P3'))
        tr.addElement(tc)
        _as_text = ''
        _as = get_prop(comp.get('properties', []), 'GOST:attack_surface')
        if _as == 'yes':
            _as_text = 'поверхность атаки'
        elif _as == 'indirect':
            _as_text = 'косвенная поверхность атаки'
        _sf_text = ''
        _sf = get_prop(comp.get('properties', []), 'GOST:security_function')
        if _sf == 'yes':
            _sf_text = 'функция безопасности'
        elif _sf == 'indirect':
            _sf_text = 'поддерживающая функции безопасности'
        tc = TableCell(stylename='Table3.A1')
        tc.addElement(P(text=(', '.join([_as_text, _sf_text]) if _as_text and _sf_text else (_as_text+_sf_text)), stylename='P3'))
        tr.addElement(tc)
        tc = TableCell(stylename='Table3.A1')
        tc.addElement(P(text=comp.get('externalReferences', [{'url':''}])[0].get('url', ''), stylename='P3'))
        tr.addElement(tc)
        item.addElement(tr)

doc.save(args.output)