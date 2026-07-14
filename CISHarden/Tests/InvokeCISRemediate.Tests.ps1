#Requires -Modules Pester
<#
    Tests de Invoke-CISRemediate: la compuerta de seguridad de alcance (sin
    -ControlId/-ControlIds/-Section/-Chapter/-All debe tirar error, nunca
    asumir "remediar todo"), que un Set-CIS_* que tira excepcion no aborta
    el resto del lote, y que -WhatIf no ejecuta remediacion real. Usa
    controles ficticios (control_id 'TEST.1'/'TEST.2') definidos localmente
    para no depender ni tocar los Set-CIS_* reales.
#>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot 'CISHarden.psd1') -Force
}

Describe 'Invoke-CISRemediate' {
    InModuleScope 'CISHarden' {

        Context 'Compuerta de alcance' {
            It 'Tira error si no se pasa ningun alcance (nunca "remediar todo" por default)' {
                { Invoke-CISRemediate } | Should -Throw
            }
        }

        Context 'Nada para remediar' {
            It 'No llama ningun Set-CIS_* si no hay controles en Fail' {
                Mock Invoke-CISAudit {
                    @([pscustomobject]@{ ControlId = 'TEST.1'; Title = 't'; Status = 'Pass' })
                }
                function Set-CIS_TEST_1 { }
                Mock Set-CIS_TEST_1 { }
                Invoke-CISRemediate -ControlId 'TEST.1' -Force
                Should -Invoke Set-CIS_TEST_1 -Times 0
            }
        }

        Context 'Resiliencia: un control que falla no aborta el resto del lote' {
            It 'Sigue remediando los demas controles aunque uno tire excepcion' {
                Mock Invoke-CISAudit {
                    @(
                        [pscustomobject]@{ ControlId = 'TEST.1'; Title = 'uno'; Status = 'Fail' },
                        [pscustomobject]@{ ControlId = 'TEST.2'; Title = 'dos'; Status = 'Fail' }
                    )
                }
                function Set-CIS_TEST_1 { throw 'boom' }
                function Set-CIS_TEST_2 { }
                Mock Set-CIS_TEST_2 { }

                $summary = Invoke-CISRemediate -ControlIds @('TEST.1', 'TEST.2') -Force

                Should -Invoke Set-CIS_TEST_2 -Times 1
                ($summary | Where-Object ControlId -eq 'TEST.1').Action | Should -Be 'Failed'
                ($summary | Where-Object ControlId -eq 'TEST.2').Action | Should -Be 'Remediated'
            }
        }

        Context 'Control sin Set-CIS_* implementada' {
            It 'Lo marca SkippedNoFunction en vez de tirar error' {
                Mock Invoke-CISAudit {
                    @([pscustomobject]@{ ControlId = 'TEST.999'; Title = 'inexistente'; Status = 'Fail' })
                }
                $summary = Invoke-CISRemediate -ControlId 'TEST.999' -Force
                ($summary | Where-Object ControlId -eq 'TEST.999').Action | Should -Be 'SkippedNoFunction'
            }
        }

        Context '-WhatIf no ejecuta remediacion real' {
            It 'Marca la accion como WhatIf y no re-audita' {
                Mock Invoke-CISAudit {
                    @([pscustomobject]@{ ControlId = 'TEST.1'; Title = 'uno'; Status = 'Fail' })
                }
                function Set-CIS_TEST_1 { }
                Mock Set-CIS_TEST_1 { }

                $summary = Invoke-CISRemediate -ControlId 'TEST.1' -WhatIf

                ($summary | Where-Object ControlId -eq 'TEST.1').Action | Should -Be 'WhatIf'
                Should -Invoke Invoke-CISAudit -Times 1  # solo el audit inicial, no la re-auditoria post-remediacion
            }
        }
    }
}
