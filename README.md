# sbom-checker

## Требования
* Python3.8 или выше

## Подготовка окружения
1. Создать и активировать виртуальное окружение.
```
python3 -m venv venv
source venv/bin/activate
```
2. Установить необходимые библиотеки.
```
pip install -r requirements.txt
```

## Использование

### sbom-checker

```
prompt> python sbom-checker.py --help

usage: sbom-checker.py [-h] [-e ERRORS] [json] filename

json schema checker

positional arguments:
  json                  schema file
  filename              file to check

optional arguments:
  -h, --help            show this help message and exit
  -e ERRORS, --errors ERRORS
                        set maximum amount of validator errors shown; default
                        is 10; set to 0 to show all errors
```

### sbom-updater

```
prompt> python sbom-updater.py --help

usage: sbom-updater.py [-h] [--props] input output

sbom file updater

positional arguments:
  input       sbom file
  output      updated file

options:
  -h, --help  show this help message and exit
  --props     add {"name": "GOST:attack_surface", "value": "yes"} and 
              {"name": "GOST:security_function", "value": "yes"} to "properties" 
              property of every component in the input file
```