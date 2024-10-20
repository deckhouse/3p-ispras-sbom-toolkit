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

usage: sbom-updater.py [-h] [--props] [--app-name APP_NAME]
                       [--app-version APP_VERSION]
                       [--manufacturer MANUFACTURER] [--ref] [--fix-all]
                       input output

sbom file updater

positional arguments:
  input                 sbom file
  output                updated file

options:
  -h, --help            show this help message and exit
  --props               add {"name": "GOST:attack_surface", "value": "yes"}
                        and {"name": "GOST:security_function", "value": "yes"}
                        to "properties" property of every component in the
                        input file
  --app-name APP_NAME   set app name
  --app-version APP_VERSION
                        set app version
  --manufacturer MANUFACTURER
                        set app manufacturer
  --ref                 add externalReferences field for every component based
                        on its purl
  --fix-all             apply all of the above commands; if the required field
                        is missing and its value is not set in command line,
                        "TODO" is used
```

### sbom-to-odt

```
prompt> python sbom-to-odt.py --help

usage: sbom-to-odt.py [-h] input output

sbom to odt converter

positional arguments:
  input       sbom file
  output      odt file

options:
  -h, --help  show this help message and exit
```