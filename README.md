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

usage: sbom-checker.py [-h] [-e ERRORS] [--check-vcs] [--check-vcs-leaf-only] [--check-source-distribution] [--format FORMAT] [--fixed-output FIXED_OUTPUT] [-v] filename

проверка sbom-файлов

positional arguments:
  filename              входной файл в формате CycloneDX JSON для проверки

options:
  -h, --help            show this help message and exit
  -e ERRORS, --errors ERRORS
                        максимальное число ошибок для вывода; по умолчанию 10;
                        установите 0 для вывода всех ошибок
  --check-vcs           проверка url типа vcs на git/svn/hg/fossil-репозиторий
                        (требуется доступ к Интернет и наличие пакетов git,
                        subversion и mercurial)
  --check-vcs-leaf-only
                        то же, что и --check-vcs, но проверяются только url в
                        листовых компонентах
  --check-source-distribution
                        проверка url типа source-distribution; проверяется
                        существование ссылки, и что ссылка указывает на архив
  --format FORMAT       --format=oss для проверки файла-перечня заимствованных
                        программных компонентов с открытым исходным кодом;
                        --format=container для проверки файла-перечня образов
                        контейнеров; по умолчанию oss
  --fixed-output FIXED_OUTPUT
                        при проверке пытаться исправлять ошибки (например дублирования) и
                        сохранить исправленную версию по указанному пути  
  -v, --verbose         подробный вывод
```

### sbom-updater

```
prompt> python sbom-updater.py --help

usage: sbom-updater.py [-h] [--props [{yes,indirect,no}]]
                       [--props-file [PROPS_FILE]] [--app-name APP_NAME]
                       [--app-version APP_VERSION] [--manufacturer MANUFACTURER]
                       [--type TYPE] [--ref] [--ref-file REF_FILE] [--use-apt]
                       [--hasher [{streebog256,streebog512}]] [--delete [DELETE]]
                       [--use-startswitch] [--fix-all] [--update OLD_SBOM] [-v]
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
  --props [{yes,indirect,no}]
                        установить значения для {"name": "GOST:attack_surface",
                        "value": "yes/indirect/no"} и {"name": "GOST:security_function",
                        "value": "yes/indirect/no"}, в поле "properties" для каждого компонента входного файла, при их отсутствии; По умолчанию "yes"
  --props-file [PROPS_FILE]
                        добавить в поле "properties" компонента, основываясь на поле "purl" компонента из указанного файла; По умолчанию ./purl_to_props.json
  --app-name APP_NAME   установить название продукта
  --app-version APP_VERSION
                        установить версию продукта
  --manufacturer MANUFACTURER
                        установить название организации — изготовителя продукта
  --type TYPE           установить тип продукта
  --ref                 установить поле "externalReferences", основываясь на
                        поле "purl" компонента; если ссылки на репозиторий не
                        было найдено, используется "sbom-updater_generated_placeholder:"
  --ref-file REF_FILE   путь до файла используемого для заполнения поля "externalReferences";
                        По умолчанию ./purl_to_vcs.json
  --use-apt             использовать apt source для получения ссылок на архивы с
                        исходными кодами для компонентов pkg:deb при невозможности
                        получить ссылку на vcs
  --hasher [{streebog256,streebog512}]
                        указать алгоритм для получения хеш-суммы, если "externalReferences" является ссылкой на архив; по умолчанию streebog256
  --delete [DELETE]     Удалить компоненты на основе "purl" указанные в файле; 
                        По умолчанию ./purl_to_delete.json
  --use-startswitch     использовать purl из файла как начало строки для заполнения "externalReferences" из файла, например ("pkg:npm/pinkie@")
  --fix-all             применить все вышеописанные опции; если необходимое
                        поле остутствует и его значение не указано,
                        используется "TODO"
  --update OLD_SBOM     предыдущая версия перечня заимствованных компонентов,
                        состав и версии которых могли устареть, но
                        метаинформацию о приложении и компонентах требуется по
                        возможности перенести в новый перечень
  -v, --verbose         подробный вывод
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

Если включен параметр `--use-startswitch`, то можно указывать purl как начало строки, например без указания версии:

```
{
  "pkg:gem/aasm@": "https://github.com/aasm/aasm",
  "pkg:nuget/NLog.Extensions.Logging@": "https://github.com/NLog/NLog.Extensions.Logging"
}
```

#### purl_to_props.json

Данный файл (путь можно задать с помощью опции `--props-file`) используется для добавление в поле `"properties"` компонента на основе purl при использовании
скрипта с опциями `--props` или `--fix-all`.
Содержимое файла должно представлять единственный объект, в котором ключ - purl, а значение это объект, содержащий свойства компонента, где ключ - название свойства, а значение - значение свойства.

Пример содержания:
```
{
    "pkg:npm/spacevm@6.5.6": {
        "GOST:attack_surface": "yes",
        "GOST:security_function": "no",
        "source_langs": "Python"
    },
    "pkg:pypi/sqlalchemy@2.0.21": {
        "GOST:security_function": "yes"
    }
}
```

Если включен параметр `--use-startswitch`, то можно указывать purl как начало строки, например без указания версии:

```
{
    "pkg:npm/spacevm@": {
        "GOST:attack_surface": "yes",
        "GOST:security_function": "no",
        "source_langs": "Python"
    },
    "pkg:pypi/sqlalchemy@": {
        "GOST:security_function": "yes"
    }
}
```

Стандартные элементы поля `"properties"`:

|название                 | значение                    | Описание                                                                  |
|-------------------------|-----------------------------|---------------------------------------------------------------------------|
|GOST:attack_surface      | "yes", "no" или "indirect"  | принадлежность компонента к поверхности атаки                             |
|GOST:security_function   | "yes", "no" или "indirect"  | принадлежность компонента к компонентам, реализующих функции безопасности |
|source_langs             | "C++", "Python, Ruby" и тд. | язык (языки) программирования, на котором написан компонент               |


#### purl_to_delete.json

Данный файл (путь можно задать с помощью опции `--delete`) используется для удаления компонентов на основе purl.
Содержимое файла должно представлять единственный массив, элементы которого - purl (или маска) удаляемого компонента.

Пример содержания:
```
[
    "pkg:gem/aasm@5.5.0",
    "pkg:npm/spacevm@6.5.6",
    "pkg:deb/space-",
]
```

### sbom-unifier

```
prompt> python sbom-unifier.py --help

usage: sbom-unifier.py [-h] --app-name APP_NAME --app-version APP_VERSION
                       --manufacturer MANUFACTURER
                       input [input ...] output

объединение sbom-файлов

positional arguments:
  input                 перечень входных файлов в формате CycloneDX JSON для
                        объединения; рекомендуется использовать файлы,
                        проверенные скриптом sbom-checker.py
  output                выходной файл, в котором продукты из входных файлов
                        объединены в список компонентов

options:
  -h, --help            show this help message and exit
  --app-name APP_NAME   название продукта
  --app-version APP_VERSION
                        версия продукта
  --manufacturer MANUFACTURER
                        название организации — изготовителя продукта
```

### sbom-to-csv

```
prompt> python sbom-to-csv.py --help

usage: sbom-to-csv.py [-h] input output

генератор таблицы компонентов в формате csv

positional arguments:
  input       входной файл, содержащий перечень заимствованных компонентов, в
              JSON формате
  output      выходной файл в формате csv, содержащий таблицу со всеми
              компонентами из входного файла

options:
  -h, --help  show this help message and exit
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
  -t, --pa-fb-ontop  помещение записей "ПА" и "ФБ" в топ таблицы
  --format FORMAT    --format=oss если входной файл — перечень заимствованных
                     программных компонентов с открытым исходным кодом;
                     --format=container если входной файл — перечень образов
                     контейнеров; по умолчанию oss

```
