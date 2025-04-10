# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

from collections import Counter
import json
import os
import platformdirs
import subprocess
import urllib.parse

SP_TIMEOUT = 60 # timeout for subpocess

pattern_dict = {
    'bitbucket.org': ((), ('commits', 'src', 'branch'), 2),
    'codeberg.org': ((('src', 'branch'), ('src', 'commit'), ('src', 'tag'), ('releases', 'tag')), ('commit',), 2),
    'github.com': ((('releases', 'tag'),), ('commit', 'blob', 'tree'), 2),
    'hg.code.sf.net': ((), ('file', 'rev', 'shortlog'), 3),
    'opendev.org': ((('src', 'branch'), ('src', 'commit'), ('src', 'tag'), ('releases', 'tag')), ('commit',), 2),
    'src.libcode.org': ((), ('src', 'commit'), 2),
    'hg.openjdk.org': ((), ('file', 'rev', 'shortlog'), 2),
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
    path_pair_list = []
    path_split = path.split('/')
    for idx in range(len(path_split) - 1):
        path_pair_list.append((path_split[idx], path_split[idx+1]))
    idx = -1
    flag = 0
    prefix = 2
    if parsed_url.netloc in pattern_dict:
        prefix = pattern_dict[parsed_url.netloc][2]
        for s in pattern_dict[parsed_url.netloc][0]:
            if len(path_pair_list) > prefix and s in path_pair_list[prefix:]:
                idx = path_pair_list[prefix:].index(s) + prefix
                flag = 1
                break
        else:
            for s in pattern_dict[parsed_url.netloc][1]:
                if len(path_split) > prefix and s in path_split[prefix:]:
                    idx = path_split[prefix:].index(s) + prefix
                    break
    else:
        for s in [('-', 'commit'), ('-', 'commits'), ('-', 'tags'), ('-', 'tree'), ('-', 'blob'), ('-', 'releases'), ('releases', 'tag')]:
            if s in path_pair_list[prefix:]:
                idx = path_pair_list[prefix:].index(s) + prefix
                flag = 1
                break
        else:
            for s in ['commit', 'blob', 'tree']:
                if s in path_split[prefix:]:
                    idx = path_split[prefix:].index(s) + prefix
                    break
    if idx > 0:
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + '/'.join(path_split[:idx])), '/'.join(path_split[idx+1+flag:])
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
            res3 = subprocess.run(f'curl --silent {url} 2>&1 | grep -iPzo "footer\\"?>\sthis\spage\swas\sgenerated\sin\sabout\s(\d+\.\d+)s\sby\sfossil"', shell=True, capture_output=True, text=True, timeout=SP_TIMEOUT)
            if 'footer' in res3.stdout:
                result = True
            elif res3.returncode != 0:
                exc_list.append(f'ERROR/FOSSIL: {res3.stderr}')
                result = False
            else:
                exc_list.append(f'ERROR/FOSSIL: didn\'t find autogenerated fossil footer on this page')
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

def load_cache():
    cache_file = platformdirs.user_cache_path('sbom-checker', ensure_exists=True) / 'check_vcs.json'
    if os.path.isfile(cache_file):
        with open(cache_file) as f:
            return json.load(f)
    return dict()

def dump_cache(data):
    cache_file = platformdirs.user_cache_path('sbom-checker', ensure_exists=True) / 'check_vcs.json'
    with open(cache_file, 'w') as f:
        json.dump(data, f)