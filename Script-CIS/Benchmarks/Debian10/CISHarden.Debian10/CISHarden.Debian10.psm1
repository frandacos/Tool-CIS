$here = $PSScriptRoot

Get-ChildItem -Path (Join-Path $here 'Private') -Filter '*.ps1' -Recurse | ForEach-Object {
    . $_.FullName
}

Get-ChildItem -Path (Join-Path $here 'Public') -Filter '*.ps1' -Recurse | ForEach-Object {
    . $_.FullName
}

# Los Test-CIS_Debian10_*/Set-CIS_Debian10_* se exportan porque los invoca
# CISHarden.Core desde otro modulo por nombre via Get-Command/&. El tag
# Debian10 en el nombre evita colisiones si en el futuro se carga junto a
# otro benchmark Unix.
Export-ModuleMember -Function 'Test-CIS_Debian10_*', 'Set-CIS_Debian10_*', 'Get-CISBenchmarkInfo_Debian10'
