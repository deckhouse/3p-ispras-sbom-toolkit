# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

from collections import Counter
import json
import os
import platformdirs
import packageurl
import packageurl.validate
import subprocess
import urllib.parse
import requests
import re

SP_TIMEOUT = 60 # timeout for subpocess

pattern_dict = {
    'bitbucket.org': [[['commits'], ['src'], ['branch']], 2],
    'codeberg.org': [[['src', 'branch'], ['src', 'commit'], ['src', 'tag'], ['releases', 'tag'], ['commit']], 2],
    'github.com': [[['releases', 'tag'], ['commit'], ['blob'], ['tree']], 2],
    'hg.code.sf.net': [[['file'], ['rev'], ['shortlog']], 3],
    'opendev.org': [[['src', 'branch'], ['src', 'commit'], ['src', 'tag'], ['releases', 'tag'], ['commit']], 2],
    'src.libcode.org': [[['src'], ['commit']], 2],
    'hg.openjdk.org': [[['file'], ['rev'], ['shortlog']], 2],
    'chromium.googlesource.com': [[['+', 'refs', 'heads'], ['+']], 1],
    'webrtc.googlesource.com': [[['+', 'refs', 'heads'], ['+']], 1],
}

def parse_repo_url(url):
    parsed_url = urllib.parse.urlparse(url)
    path = parsed_url.path.strip('/')
    query = urllib.parse.parse_qs(parsed_url.query)
    if 'commit' in query:
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), query['commit'][0]
    if 'tag' in query:
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), query['tag'][0]
    if parsed_url.netloc == 'git.altlinux.org':
        query = urllib.parse.parse_qs(parsed_url.query, separator=';')
        fpath = ''
        commit = ''
        if 'f' in query:
            fpath = query['f'][0]
        if 'h' in query:
            commit = query['h'][0]
        elif 'hb' in query:
            commit = query['hb'][0]
        if fpath:
            if not commit:
                commit = 'HEAD'
            return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), commit+'/'+fpath
        else:
            return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), commit
    if parsed_url.netloc == 'git.netfilter.org':
        query = urllib.parse.parse_qs(parsed_url.query)
        commit = ''
        if 'id' in query:
            commit = query['id'][0]
        elif 'h' in query:
            commit = query['h'][0]
        path_split = path.split('/')
        if len(path_split) <= 2:
            return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path_split[0]), commit
        if not commit:
            commit = 'HEAD'
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path_split[0]), commit+'/'+'/'.join(path_split[2:])
    if parsed_url.netloc == 'gitbox.apache.org':
        try:
            query = urllib.parse.parse_qs(parsed_url.query, separator=';')
        except Exception:
            query = urllib.parse.parse_qs(parsed_url.query)
        fpath = ''
        commit = ''
        if 'p' in query:
            path = os.path.join(path, query['p'][0])
        if 'f' in query:
            fpath = query['f'][0]
        if 'h' in query:
            commit = query['h'][0]
        elif 'hb' in query:
            commit = query['hb'][0]
        if fpath:
            if not commit:
                commit = 'HEAD'
            return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), commit+'/'+fpath
        else:
            return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), commit
    path_split = path.split('/')
    idx = [-1,-1]
    prefix = 2
    if parsed_url.netloc in pattern_dict:
        prefix = pattern_dict[parsed_url.netloc][1]
        for s in pattern_dict[parsed_url.netloc][0]:
            for i in range(len(path_split[prefix:])):
                if path_split[prefix:][i:i+len(s)] == s:
                    idx = [prefix+i, prefix+i+len(s)]
                    break
            else:
                continue
            break
    else:
        for s in [['-', 'commit'], ['-', 'commits'], ['-', 'tags'], ['-', 'tree'], ['-', 'blob'], ['-', 'releases'], ['releases', 'tag'], ['commit'], ['blob'], ['tree']]:
            for i in range(len(path_split[prefix:])):
                if path_split[prefix:][i:i+len(s)] == s:
                    idx = [prefix+i, prefix+i+len(s)]
                    break
            else:
                continue
            break
    if idx[0] > 0:
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + '/'.join(path_split[:idx[0]])), '/'.join(path_split[idx[1]:])
    return None

def check_repo(url):
    result = False
    exc_list = []
    try:
        res0 = subprocess.run(f'git ls-remote {url}', shell=True, capture_output=True, text=True, timeout=SP_TIMEOUT)
        if res0.returncode != 0:
            exc_list.append(f'ERROR/GIT: {res0.stderr}')
            result = False
        else:
            result = True
    except Exception as e:
        exc_list.append(f'ERROR/GIT: {e}')
        result = False
    if not result:
        try:
            res1 = subprocess.run(f'svn ls {url}', shell=True, capture_output=True, text=True, timeout=SP_TIMEOUT)
            if res1.returncode != 0:
                exc_list.append(f'ERROR/SVN: {res1.stderr}')
                result = False
            else:
                result = True
        except Exception as e:
            exc_list.append(f'ERROR/SVN: {e}')
            result = False
    if not result:
        try:
            res2 = subprocess.run(f'hg identify {url}', shell=True, capture_output=True, text=True, timeout=SP_TIMEOUT)
            if res2.returncode != 0:
                exc_list.append(f'ERROR/HG: {res2.stderr}')
                result = False
            else:
                result = True
        except Exception as e:
            exc_list.append(f'ERROR/HG: {e}')
            result = False
    if not result:
        try:
            res3 = requests.get(url, timeout=SP_TIMEOUT)
            if res3.status_code == 200:
                if re.search(r'footer\"?>\sthis\spage\swas\sgenerated\sin\sabout\s(\d+\.\d+)s\sby\sfossil', res3.text, re.I):
                    result = True
                else:
                    exc_list.append(f'ERROR/FOSSIL: didn\'t find autogenerated fossil footer on this page')
                    result = False
            else:
                exc_list.append(f'ERROR/FOSSIL: {url} returned code {res3.status_code}')
                result = False
        except Exception as e:
            exc_list.append(f'ERROR/FOSSIL: {e}')
            result = False
    return result, '\n'.join(exc_list)

def validate_no_duplicate_keys(list_of_pairs):
    key_count = Counter(k for k,v in list_of_pairs)
    duplicate_keys = ', '.join(k for k,v in key_count.items() if v>1)

    if len(duplicate_keys) != 0:
        raise ValueError(f'Duplicate key(s) in file: {duplicate_keys}')
    return dict(list_of_pairs)

def opener(filename, pairs=False):
    encoding = None
    try:
        with open(filename) as f:
            data = json.load(f, object_pairs_hook=(validate_no_duplicate_keys if pairs else None))
    except UnicodeDecodeError:
        with open(filename, encoding='utf-8') as f: # duplicate keys detection
            data = json.load(f, object_pairs_hook=(validate_no_duplicate_keys if pairs else None))
        encoding = 'utf-8'
    except json.decoder.JSONDecodeError:
        with open(filename, encoding='utf-8-sig') as f: # duplicate keys detection
            data = json.load(f, object_pairs_hook=(validate_no_duplicate_keys if pairs else None))
        encoding = 'utf-8-sig'
    return data, encoding

def load_cache(type):
    cache_file = platformdirs.user_cache_path('sbom-checker', ensure_exists=True) / f"check_{type.replace('-', '_')}.json"
    if os.path.isfile(cache_file):
        with open(cache_file) as f:
            return json.load(f)
    return dict()

def dump_cache(type, data):
    cache_file = platformdirs.user_cache_path('sbom-checker', ensure_exists=True) / f"check_{type.replace('-', '_')}.json"
    with open(cache_file, 'w') as f:
        json.dump(data, f)

def is_archive_url(session, url, timeout=10):
    """Проверяет, является ли URL архивом"""
    archive_mime_types = {
        'application/zip', 'application/x-rar-compressed', 
        'application/x-7z-compressed', 'application/x-tar',
        'application/gzip', 'application/x-bzip2', 
        'application/x-xz', 'application/x-zip-compressed',
        'application/octet-stream', 'application/x-msdownload',
        'application/x-rpm', 'application/java-archive',
        'application/vnd.rar', 'application/zstd'
    }
    
    archive_extensions = {
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', 
        '.xz', '.tgz', '.tbz2', '.tar.gz', '.tar.bz2', 
        '.tar.xz', '.zipx', '.iso', '.cab', '.arj', '.src.rpm', '.jar',
        '.tar.lz', '.tlz', '.tar.Z', '.Z', '.tar.lzma', '.whl', '.rpm',
        '.src.rock', '.cpio', '.tzr.zst', '.zst'
    }
    exc_list = []
    result = False
    try:
        # Пробуем HEAD запрос
        response = session.head(url, allow_redirects=True, timeout=timeout)
        # Если HEAD возвращает 405 (Method Not Allowed), пробуем GET
        if response.status_code == 405:
            response = session.get(url, stream=True, timeout=timeout, allow_redirects=True, headers={'Range': 'bytes=0-1024'})
        response.raise_for_status()

        # Проверка Content-Type
        content_type = response.headers.get('Content-Type', '').split(';')[0].strip().lower()
        if content_type not in archive_mime_types:
            exc_list.append(f"ERROR: MIME тип содержимого не соответствует типу архива: {content_type}")
            result = False
        else:
            result = True

        # Проверка расширения в URL
        if not result:
            parsed_url = urllib.parse.urlparse(url)
            path = parsed_url.path
            filename = path.split('/')[-1].lower() if path else ''
            if not any(filename.endswith(ext) for ext in archive_extensions):
                exc_list.append(f"ERROR: Расширение файла в URL не соответствует расширению архива.")
                result = False
            else:
                result = True

        # Проверка Content-Disposition
        if not result:
            content_disposition = response.headers.get('Content-Disposition', '')
            if content_disposition:
                # Извлечение имени файла
                filenames = re.findall(r'filename\*?=["\']?(?:UTF-\d["\']?)?([^;"\'\n]+)', content_disposition, re.IGNORECASE)
                if not filenames:
                    filenames = re.findall(r'filename=["\']?([^;"\'\n]+)', content_disposition, re.IGNORECASE)
                for name in filenames:
                    name = name.strip().lower()
                    if not any(name.endswith(ext) for ext in archive_extensions):
                        exc_list.append(f"ERROR: Расширение файла в Content-Disposition не соответствует расширению архива.")
                        result = False
                    else:
                        result = True
        return result, '\n'.join(exc_list)
    
    except Exception as e:
        exc_list.append(f"ERROR: {str(e)}")
        result = False
        return result, '\n'.join(exc_list)
    finally:
        if 'response' in locals():
            response.close()

def get_prop(arr, name):
    for elem in arr:
        if elem.get('name', '') == name:
            return elem.get('value', '')
    return ''

def combine_source_langs(sl1, sl2):
    if sl1 and not sl2 or not sl1 and sl2:
        return sl1 or sl2
    result = [sl.strip() for sl in sl1.split(',')]
    for sl in sl2.split(','):
        sl = sl.strip()
        if not sl in result:
            result.append(sl)
    return ', '.join(result)

class BazelTypeDefinition(packageurl.validate.BasePurlType):
    type = "bazel"
    type_name = "Bazel modules"
    description = """Bazel modules as specified at https://bazel.build/external/module"""
    use_repository = True
    default_repository_url = "https://bcr.bazel.build"
    namespace_requirement = "prohibited"
    allowed_qualifiers = {"repository_url"}
    namespace_case_sensitive = False
    name_case_sensitive = False
    version_case_sensitive = True
    purl_pattern = "pkg:bazel/.*"
class BrewTypeDefinition(packageurl.validate.BasePurlType):
    type = "brew"
    type_name = "Homebrew"
    description = """Homebrew packages for macOS and Linux"""
    use_repository = True
    default_repository_url = "https://formulae.brew.sh/"
    namespace_requirement = "optional"
    allowed_qualifiers = {"repository_url"}
    namespace_case_sensitive = False
    name_case_sensitive = False
    version_case_sensitive = True
    purl_pattern = "pkg:brew/.*"
class ChromeExtensionTypeDefinition(packageurl.validate.BasePurlType):
    type = "chrome-extension"
    type_name = "Chrome Browser Extensions"
    description = """Chrome Browser Extensions. Note: there are currently no officially documented APIs, further there appears to be no way to query different versions of a package - there only seems to be responses on the latest version. To this end the version component of a chrome purl can be optional. Two known data sources are a sitemap which can be crawled to discover (some) extensions at https://chromewebstore.google.com/sitemap, and an 'updatecheck' API which you can read about here https://github.com/Rob--W/crxviewer , and perhaps here https://github.com/chromium/chromium/blob/main/docs/updater/protocol_3_1.md"""
    use_repository = True
    default_repository_url = "https://chromewebstore.google."
    namespace_requirement = "prohibited"
    allowed_qualifiers = {"repository_url"}
    namespace_case_sensitive = False
    name_case_sensitive = False
    version_case_sensitive = True
    purl_pattern = "pkg:chrome-extension/.*"
    @classmethod
    def validate_using_type_rules(cls, purl, strict=False):
        from packageurl import ValidationMessage
        from packageurl import ValidationSeverity
        if not re.match(r"^[a-p]{32}$", purl.name):
            yield ValidationMessage(
                severity=ValidationSeverity.WARNING,
                message=f"Name is invalid for purl type: {cls.type!r}. The name is 32 characters in the range a-p (base16-encoded with letters instead of hex digits)",
            )
        if purl.version and not re.match(r"^\d+(\.\d+){0,3}$", purl.version):
            yield ValidationMessage(
                severity=ValidationSeverity.WARNING,
                message=f"Version is invalid for purl type: {cls.type!r}. The chrome extension version is semver-like but 1-4 segments",
            )
        messages = super().validate_using_type_rules(purl, strict)
        if messages:
            yield from messages
class GitTypeDefinition(packageurl.validate.BasePurlType):
    type = "git"
    type_name = "Git"
    description = """Git-based source packages"""
    use_repository = True
    default_repository_url = ""
    namespace_requirement = "required"
    allowed_qualifiers = {"repository_url"}
    namespace_case_sensitive = True
    name_case_sensitive = True
    version_case_sensitive = True
    purl_pattern = "pkg:git/.*"
class JuliaTypeDefinition(packageurl.validate.BasePurlType):
    type = "julia"
    type_name = "Julia Package"
    description = """Julia Packages"""
    use_repository = True
    default_repository_url = "https://github.com/JuliaRegistries/General"
    namespace_requirement = "prohibited"
    allowed_qualifiers = {"repository_url", "uuid"}
    namespace_case_sensitive = False
    name_case_sensitive = True
    version_case_sensitive = True
    purl_pattern = "pkg:julia/.*"
    @classmethod
    def validate_using_type_rules(cls, purl, strict=False):
        from packageurl import ValidationMessage
        from packageurl import ValidationSeverity
        if not "uuid" in purl.qualifiers:
            yield ValidationMessage(
                severity=ValidationSeverity.WARNING,
                message=f"\'uuid\' qualifier is required for purl type: {cls.type!r}.",
            )
        messages = super().validate_using_type_rules(purl, strict)
        if messages:
            yield from messages
class OpamTypeDefinition(packageurl.validate.BasePurlType):
    type = "opam"
    type_name = "Opam package"
    description = """Opam packages"""
    use_repository = True
    default_repository_url = "https://opam.ocaml.org"
    namespace_requirement = "prohibited"
    allowed_qualifiers = {"repository_url"}
    namespace_case_sensitive = False
    name_case_sensitive = True
    version_case_sensitive = True
    purl_pattern = "pkg:opam/.*"
class OtpTypeDefinition(packageurl.validate.BasePurlType):
    type = "otp"
    type_name = "BEAM/OTP Application"
    description = """BEAM/OTP applications written in Elixir, Erlang, Gleam and other BEAM languages",
  "note": "- If the component was fetched from a Hex repository, prefer a ``hex`` purl\n  because Hex provides a global, collision-free namespace that uniquely ties\n  the version to the published source.\n- There is no default package repository. When the application can be\n  fetched from a known location, add a general qualifier such as\n  `repository_url`, `download_url` or `vcs_url`."""
    use_repository = False
    default_repository_url = ""
    namespace_requirement = "prohibited"
    allowed_qualifiers = {"repository_url", "platform", "arch"}
    namespace_case_sensitive = False
    name_case_sensitive = False
    version_case_sensitive = True
    purl_pattern = "pkg:otp/.*"
class VcpkgTypeDefinition(packageurl.validate.BasePurlType):
    type = "vcpkg"
    type_name = "Vcpkg C/C++ packages"
    description = """Packages from the vcpkg C/C++ package manager."""
    use_repository = True
    default_repository_url = "https://github.com/microsoft/vcpkg/"
    namespace_requirement = "prohibited"
    allowed_qualifiers = {"repository_url", "port_version", "repository_revision", "triplet"}
    namespace_case_sensitive = False
    name_case_sensitive = False
    version_case_sensitive = True
    purl_pattern = "pkg:vcpkg/.*"
class VscodeExtensionTypeDefinition(packageurl.validate.BasePurlType):
    type = "vscode-extension"
    type_name = "VS Code Extension packages"
    description = """VS Code Extension packages"""
    use_repository = True
    default_repository_url = "https://marketplace.visualstudio.com/vscode-extension"
    namespace_requirement = "required"
    allowed_qualifiers = {"repository_url", "platform"}
    namespace_case_sensitive = False
    name_case_sensitive = False
    version_case_sensitive = False
    purl_pattern = "pkg:vscode-extension/.*"
class YoctoTypeDefinition(packageurl.validate.BasePurlType):
    type = "yocto"
    type_name = "Yocto Project"
    description = """Yocto Project recipies"""
    use_repository = True
    default_repository_url = ""
    namespace_requirement = "optional"
    allowed_qualifiers = {"repository_url", "layer_version"}
    namespace_case_sensitive = False
    name_case_sensitive = True
    version_case_sensitive = True
    purl_pattern = "pkg:yocto/.*"

packageurl.validate.DEFINITIONS_BY_TYPE['bazel'] = BazelTypeDefinition
packageurl.validate.DEFINITIONS_BY_TYPE['brew'] = BrewTypeDefinition
packageurl.validate.DEFINITIONS_BY_TYPE['chrome-extension'] = ChromeExtensionTypeDefinition
packageurl.validate.DEFINITIONS_BY_TYPE['git'] = GitTypeDefinition
packageurl.validate.DEFINITIONS_BY_TYPE['julia'] = JuliaTypeDefinition
packageurl.validate.DEFINITIONS_BY_TYPE['opam'] = OpamTypeDefinition
packageurl.validate.DEFINITIONS_BY_TYPE['otp'] = OtpTypeDefinition
packageurl.validate.DEFINITIONS_BY_TYPE['vcpkg'] = VcpkgTypeDefinition
packageurl.validate.DEFINITIONS_BY_TYPE['vscode-extension'] = VscodeExtensionTypeDefinition
packageurl.validate.DEFINITIONS_BY_TYPE['yocto'] = YoctoTypeDefinition
for k, v in packageurl.validate.DEFINITIONS_BY_TYPE.items():
    v.allowed_qualifiers |= {"checksum", "download_url", "file_name", "vcs_url", "vers"}

def check_purl(purl):
    result = packageurl.PackageURL.validate_string(purl, True)
    if result:
        return False, "\n".join([m.message for m in result])
    else:
        return True, ""