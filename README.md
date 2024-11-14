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

проверка sbom-файлов

positional arguments:
  json                  файл-спецификация; по умолчанию ./schema.json
  filename              входной файл в формате CycloneDX JSON для проверки

options:
  -h, --help            show this help message and exit
  -e ERRORS, --errors ERRORS
                        максимальное число ошибок для вывода; по умолчанию 10;
                        установите 0 для вывода всех ошибок
```

### sbom-updater

```
prompt> python sbom-updater.py --help

usage: sbom-updater.py [-h] [--props] [--app-name APP_NAME]
                       [--app-version APP_VERSION]
                       [--manufacturer MANUFACTURER] [--ref] [--fix-all]
                       [--update OLD_SBOM] [-v]
                       input output

изменение sbom-файлов

positional arguments:
  input                 входной файл в формате CycloneDX JSON, содержащий
                        актуальную информацию о составе заимствованных
                        компонентов
  output                выходной файл с дооформленным переченем заимствованных
                        компонентов

options:
  -h, --help            show this help message and exit
  --props               добавить {"name": "GOST:attack_surface", "value":
                        "yes"} и {"name": "GOST:security_function", "value":
                        "yes"} в поле "properties" для каждого компонента
                        входного файла, при их отсутствии
  --app-name APP_NAME   установить название продукта
  --app-version APP_VERSION
                        установить версию продукта
  --manufacturer MANUFACTURER
                        установить название организации — изготовителя
                        продукта
  --ref                 установить поле "externalReferences", основываясь на
                        поле "purl" компонента
  --fix-all             применить все вышеописанные опции; если необходимое
                        поле остутствует и его значение не указано,
                        используется "TODO"
  --update OLD_SBOM     предыдущая версия перечня заимствованных компонентов,
                        состав и версии которых могли устареть, но
                        метаинформацию о приложении и компонентах требуется по
                        возможности перенести в новый перечень
  -v, --verbose         побробный вывод
```
#### purl_to_vcs.json

Данный файл используется для заполнения поля `"externalReferences"` компонент на основе purl при использовании скрипта с опциями `--ref` или `--fix-all`.
Содержимое файла должно представлять единственный объект, в котором ключ — purl, а значение — ссылка на репозиторий, где хранятся исходные файлы компонента.

Пример содержания:
```
{
  "pkg:gem/aasm@5.5.0": "https://github.com/aasm/aasm",
  "pkg:nuget/NLog.Extensions.Logging@5.3.12": "https://github.com/NLog/NLog.Extensions.Logging"
}
```

### sbom-to-odt

```
prompt> python sbom-to-odt.py --help

usage: sbom-to-odt.py [-h] input output

генератор таблицы компонентов в формате odt

positional arguments:
  input       входной файл, содержащий перечень заимствованных компонентов, в
              JSON формате
  output      выходной файл в формате odt, содержащий таблицу со всеми
              компонентами из входного файла

options:
  -h, --help  show this help message and exit
```
