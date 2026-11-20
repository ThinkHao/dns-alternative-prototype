$ErrorActionPreference = 'Stop'

$venvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (Test-Path -LiteralPath $venvPython) {
    $pythonPath = $venvPython
} else {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        throw '未找到 Python 3。请安装 Python 3 后重新运行。'
    }
    $pythonPath = $python.Source
}

& $pythonPath -c 'import dns' 2>$null
if ($LASTEXITCODE -ne 0) {
    throw '缺少 dnspython 依赖。请先运行：python -m pip install -r requirements.txt'
}

& $pythonPath -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>$null
if ($LASTEXITCODE -ne 0) {
    throw '需要 Python 3.11 或更高版本。'
}

& $pythonPath (Join-Path $PSScriptRoot 'server.py')
