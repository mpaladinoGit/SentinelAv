# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:/Users/marco/projetos/Mypdf/SentinelAV/main.py'],
    pathex=[],
    binaries=[],
    datas=[('C:/Users/marco/projetos/Mypdf/SentinelAV/assets', 'assets')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['torch', 'torchaudio', 'transformers', 'scipy', 'sklearn', 'matplotlib', 'tensorboard', 'playwright', 'av', 'librosa', 'numba', 'llvmlite', 'sympy', 'oci', 'fastapi', 'uvicorn', 'faster_whisper', 'TTS', 'cv2', 'onnxruntime', 'fitz'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='SentinelAV',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['C:/Users/marco/projetos/Mypdf/SentinelAV/assets/shield.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='SentinelAV',
)
