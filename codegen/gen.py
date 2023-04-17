#!/usr/bin/env python3.11

import os
import re
import yaml
from jinja2 import Environment, FileSystemLoader

if __name__ == "__main__":
    # yaml = YAML()
    currfile = os.path.abspath(__file__)
    # Get the directory containing the current file
    basepath = os.path.dirname(currfile)
    c_src_root = os.path.join(basepath, '..', 'c_src')
    with open(os.path.join(basepath, 'config.yaml'), 'r') as f:
        config = yaml.safe_load(f)
    # print(config)

    # Load templates file from templtes folder 
    env = Environment(loader = FileSystemLoader(os.path.join(basepath, 'templates')), trim_blocks=True, lstrip_blocks=True)
    make_outputs = []
    kem_h_template = env.get_template('kem.h.j2')
    kem_c_template = env.get_template('kem.c.j2')
    sign_h_template = env.get_template('sign.h.j2')
    sign_c_template = env.get_template('sign.c.j2')
    nif_c_template = env.get_template('nif.c.j2')
    nif_erl_template = env.get_template('nif.erl.j2')
    nif_suite_erl_template = env.get_template('nif_SUITE.erl.j2')
    makefile_template = env.get_template('Makefile.j2')
    readme_template = env.get_template('README.md.j2')
    for kem_data in config['kem_algorithms']:
        kem_meta_file = os.path.join(basepath, '..', 'c_deps', 'PQClean', kem_data['src'], '..', 'META.yml')
        with open(kem_meta_file, 'r') as f:
            kem_meta = yaml.safe_load(f)
        kem_makefile = os.path.join(basepath, '..', 'c_deps', 'PQClean', kem_data['src'], 'Makefile')
        headers_pattern = r'HEADERS\s*=\s*(.+)$'
        objects_pattern = r'OBJECTS\s*=\s*(.+)$'
        kem_headers = []
        kem_objects = []
        kem_sources = []
        with open(kem_makefile, 'r') as f:
            for line in f.readlines():
                headers_captures = re.search(headers_pattern, line)
                if headers_captures:
                    kem_headers.extend(headers_captures.group(1).split())
                objects_captures = re.search(objects_pattern, line)
                if objects_captures:
                    kem_objects.extend(objects_captures.group(1).split())
        for kem_object in kem_objects:
            kem_base_file, _ = os.path.splitext(kem_object)
            kem_source = kem_base_file + '.c'
            kem_sources.append(kem_source)
        kem_data['meta'] = kem_meta
        kem_h_file = os.path.join(c_src_root, 'nif', f"pqclean_nif_{kem_data['lower_c_name']}.h")
        kem_c_file = os.path.join(c_src_root, 'nif', f"pqclean_nif_{kem_data['lower_c_name']}.c")
        with open(kem_h_file, 'w') as f:
            print(kem_h_file)
            f.write(kem_h_template.render(kem_data))
        with open(kem_c_file, 'w') as f:
            print(kem_c_file)
            f.write(kem_c_template.render(kem_data))
        make_outputs.append({
            'target': f"{kem_data['pqclean_prefix']}_OUTPUT",
            'libname': kem_data['libname'],
            'src': kem_data['src'],
            'headers': kem_headers,
            'objects': kem_objects,
            'sources': kem_sources,
        })
    for sign_data in config['sign_algorithms']:
        sign_meta_file = os.path.join(basepath, '..', 'c_deps', 'PQClean', sign_data['src'], '..', 'META.yml')
        with open(sign_meta_file, 'r') as f:
            sign_meta = yaml.safe_load(f)
        if 'seedable' in sign_data and sign_data['seedable'] and 'length-seed' not in sign_meta:
            sign_api_h_file = os.path.join(basepath, '..', 'c_deps', 'PQClean', sign_data['src'], 'api.h')
            pattern = r'_CRYPTO_SEEDBYTES\s+(\d+)'
            with open(sign_api_h_file, 'r') as f:
                for line in f.readlines():
                    captures = re.search(pattern, line)
                    if captures:
                        sign_meta['length-seed'] = int(captures.group(1))
                        break
        sign_makefile = os.path.join(basepath, '..', 'c_deps', 'PQClean', sign_data['src'], 'Makefile')
        headers_pattern = r'HEADERS\s*=\s*(.+)$'
        objects_pattern = r'OBJECTS\s*=\s*(.+)$'
        sign_headers = []
        sign_objects = []
        sign_sources = []
        with open(sign_makefile, 'r') as f:
            for line in f.readlines():
                headers_captures = re.search(headers_pattern, line)
                if headers_captures:
                    sign_headers.extend(headers_captures.group(1).split())
                objects_captures = re.search(objects_pattern, line)
                if objects_captures:
                    sign_objects.extend(objects_captures.group(1).split())
        for sign_object in sign_objects:
            sign_base_file, _ = os.path.splitext(sign_object)
            sign_source = sign_base_file + '.c'
            sign_sources.append(sign_source)
        sign_data['meta'] = sign_meta
        sign_h_file = os.path.join(c_src_root, 'nif', f"pqclean_nif_{sign_data['lower_c_name']}.h")
        sign_c_file = os.path.join(c_src_root, 'nif', f"pqclean_nif_{sign_data['lower_c_name']}.c")
        with open(sign_h_file, 'w') as f:
            print(sign_h_file)
            f.write(sign_h_template.render(sign_data))
        with open(sign_c_file, 'w') as f:
            print(sign_c_file)
            f.write(sign_c_template.render(sign_data))
        make_outputs.append({
            'target': f"{sign_data['pqclean_prefix']}_OUTPUT",
            'libname': sign_data['libname'],
            'src': sign_data['src'],
            'headers': sign_headers,
            'objects': sign_objects,
            'sources': sign_sources,
        })
    nif_c_file = os.path.join(c_src_root, 'nif', 'pqclean_nif.c')
    with open(nif_c_file, 'w') as f:
        print(nif_c_file)
        f.write(nif_c_template.render(config))
    nif_erl_file = os.path.join(basepath, '..', 'src', 'pqclean_nif.erl')
    with open(nif_erl_file, 'w') as f:
        print(nif_erl_file)
        f.write(nif_erl_template.render(config))
    nif_suite_erl_file = os.path.join(basepath, '..', 'test', 'pqclean_nif_SUITE.erl')
    with open(nif_suite_erl_file, 'w') as f:
        print(nif_suite_erl_file)
        f.write(nif_suite_erl_template.render(config))
    make_file = os.path.join(c_src_root, 'Makefile')
    with open(make_file, 'w') as f:
        print(make_file)
        print(make_outputs)
        f.write(makefile_template.render({'make_outputs': make_outputs}))
    readme_file = os.path.join(basepath, '..', 'README.md')
    with open(readme_file, 'w') as f:
        print(readme_file)
        f.write(readme_template.render(config))
