# -*- mode: python ; coding: utf-8 -*-
"""
Spec-файл для сборки LandauVPN под Windows
Используйте: pyinstaller landauvpn-windows.spec --clean
"""

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('vpn_servers.json', 'landauvpn'),
    ],
    hiddenimports=[
        'customtkinter',
        'requests',
        'PIL',
        'PIL.Image',
        'packaging.version',
        'landauvpn.core.models',
        'landauvpn.core.vpn_controller',
        'landauvpn.gui.main_window',
        'landauvpn.proxy.controller',
        'landauvpn.utils.config',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'scipy',
        'pandas',
        'numpy.testing',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='LandauVPN',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # False для GUI приложения (без консольного окна)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Для добавления иконки: icon='icon.ico'
)
