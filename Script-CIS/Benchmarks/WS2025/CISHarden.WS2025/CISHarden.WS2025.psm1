$here = $PSScriptRoot

Get-ChildItem -Path (Join-Path $here 'Private') -Filter '*.ps1' -Recurse | ForEach-Object {
    . $_.FullName
}

Get-ChildItem -Path (Join-Path $here 'Public') -Filter '*.ps1' -Recurse | ForEach-Object {
    . $_.FullName
}

# Los Test-CIS_WS2025_*/Set-CIS_WS2025_* se exportan (a diferencia del
# viejo modulo unico) porque ahora los invoca CISHarden.Core desde otro
# modulo por nombre via Get-Command/&. El tag WS2025 en el nombre evita
# colisiones si en el futuro se carga junto a otro benchmark (ej. WS2022).
Export-ModuleMember -Function 'Test-CIS_WS2025_*', 'Set-CIS_WS2025_*', 'Get-CISBenchmarkInfo_WS2025'
