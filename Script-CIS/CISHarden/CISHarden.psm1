$here = $PSScriptRoot

Get-ChildItem -Path (Join-Path $here 'Private') -Filter '*.ps1' -Recurse | ForEach-Object {
    . $_.FullName
}

Get-ChildItem -Path (Join-Path $here 'Public') -Filter '*.ps1' -Recurse | ForEach-Object {
    . $_.FullName
}

Export-ModuleMember -Function 'Invoke-CISAudit', 'Invoke-CISRemediate'
