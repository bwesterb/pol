import pkg_resources
import subprocess

# TODO document instructions

subprocess.call(['../src/version/__init__.py'])

a = Analysis(['../src/main.py'],
             pathex=['.'],
             hiddenimports=[],
             hookspath=None,
             excludes=['gtk', 'Tkinter'])

for fn in ('adjacency_graphs.json', 'frequency_lists.json'):
     a.datas.append(('zxcvbn/generated/' + fn,
                pkg_resources.resource_filename('zxcvbn', 'generated/' + fn),
                'DATA'))

a.datas.append(('RELEASE-VERSION',
                '../src/version/RELEASE-VERSION',
                'DATA'))

pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='pol',
          debug=False,
          strip=None,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=None,
               upx=True,
               name='pol')

# vim: ft=python
