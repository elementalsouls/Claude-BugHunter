param([int]$Port=8765,[string]$Base=(Join-Path $HOME '.bughunter-engagements'))
$ErrorActionPreference='Stop'
$Server=Join-Path (Split-Path -Parent $PSScriptRoot) 'dashboard/server.py'
if (Get-Command py -ErrorAction SilentlyContinue) { & py -3 $Server --port $Port --base $Base }
else { & python $Server --port $Port --base $Base }
