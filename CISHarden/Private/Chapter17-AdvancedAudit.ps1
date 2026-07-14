# CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Capitulo 17
# Advanced Audit Policy Configuration (34 controles). Fuente: cis2025.md
# paginas ~380-458. Todo via auditpol.exe (AuditPolicyEngine.ps1). Los
# nombres de subcategoria son los oficiales de auditpol (estables desde
# Windows Vista/Server 2008), no siempre coinciden textualmente con el
# nombre CIS (ej. 17.3.1 "Audit PNP Activity" -> subcategoria "Plug and Play
# Events").

# ===================== 17.1 Account Logon =====================

function Test-CIS_17_1_1 { Test-CISAuditPolicy -ControlId '17.1.1' -Title "Ensure 'Audit Credential Validation' is set to 'Success and Failure'" -Subcategory 'Credential Validation' -Mode SuccessAndFailure }
function Set-CIS_17_1_1 { Set-CISAuditPolicyForMode -Subcategory 'Credential Validation' -Mode SuccessAndFailure }

function Test-CIS_17_1_2 { Test-CISAuditPolicy -ControlId '17.1.2' -Title "Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure' (DC Only)" -Subcategory 'Kerberos Authentication Service' -Mode SuccessAndFailure -Scope DC }
function Set-CIS_17_1_2 { Set-CISAuditPolicyForMode -Subcategory 'Kerberos Authentication Service' -Mode SuccessAndFailure -Scope DC }

function Test-CIS_17_1_3 { Test-CISAuditPolicy -ControlId '17.1.3' -Title "Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure' (DC Only)" -Subcategory 'Kerberos Service Ticket Operations' -Mode SuccessAndFailure -Scope DC }
function Set-CIS_17_1_3 { Set-CISAuditPolicyForMode -Subcategory 'Kerberos Service Ticket Operations' -Mode SuccessAndFailure -Scope DC }

# ===================== 17.2 Account Management =====================

function Test-CIS_17_2_1 { Test-CISAuditPolicy -ControlId '17.2.1' -Title "Ensure 'Audit Application Group Management' is set to 'Success and Failure'" -Subcategory 'Application Group Management' -Mode SuccessAndFailure }
function Set-CIS_17_2_1 { Set-CISAuditPolicyForMode -Subcategory 'Application Group Management' -Mode SuccessAndFailure }

function Test-CIS_17_2_2 { Test-CISAuditPolicy -ControlId '17.2.2' -Title "Ensure 'Audit Computer Account Management' is set to include 'Success' (DC only)" -Subcategory 'Computer Account Management' -Mode IncludeSuccess -Scope DC }
function Set-CIS_17_2_2 { Set-CISAuditPolicyForMode -Subcategory 'Computer Account Management' -Mode IncludeSuccess -Scope DC }

function Test-CIS_17_2_3 { Test-CISAuditPolicy -ControlId '17.2.3' -Title "Ensure 'Audit Distribution Group Management' is set to include 'Success' (DC only)" -Subcategory 'Distribution Group Management' -Mode IncludeSuccess -Scope DC }
function Set-CIS_17_2_3 { Set-CISAuditPolicyForMode -Subcategory 'Distribution Group Management' -Mode IncludeSuccess -Scope DC }

function Test-CIS_17_2_4 { Test-CISAuditPolicy -ControlId '17.2.4' -Title "Ensure 'Audit Other Account Management Events' is set to include 'Success' (DC only)" -Subcategory 'Other Account Management Events' -Mode IncludeSuccess -Scope DC }
function Set-CIS_17_2_4 { Set-CISAuditPolicyForMode -Subcategory 'Other Account Management Events' -Mode IncludeSuccess -Scope DC }

function Test-CIS_17_2_5 { Test-CISAuditPolicy -ControlId '17.2.5' -Title "Ensure 'Audit Security Group Management' is set to include 'Success'" -Subcategory 'Security Group Management' -Mode IncludeSuccess }
function Set-CIS_17_2_5 { Set-CISAuditPolicyForMode -Subcategory 'Security Group Management' -Mode IncludeSuccess }

function Test-CIS_17_2_6 { Test-CISAuditPolicy -ControlId '17.2.6' -Title "Ensure 'Audit User Account Management' is set to 'Success and Failure'" -Subcategory 'User Account Management' -Mode SuccessAndFailure }
function Set-CIS_17_2_6 { Set-CISAuditPolicyForMode -Subcategory 'User Account Management' -Mode SuccessAndFailure }

# ===================== 17.3 Detailed Tracking =====================

function Test-CIS_17_3_1 { Test-CISAuditPolicy -ControlId '17.3.1' -Title "Ensure 'Audit PNP Activity' is set to include 'Success'" -Subcategory 'Plug and Play Events' -Mode IncludeSuccess }
function Set-CIS_17_3_1 { Set-CISAuditPolicyForMode -Subcategory 'Plug and Play Events' -Mode IncludeSuccess }

function Test-CIS_17_3_2 { Test-CISAuditPolicy -ControlId '17.3.2' -Title "Ensure 'Audit Process Creation' is set to include 'Success'" -Subcategory 'Process Creation' -Mode IncludeSuccess }
function Set-CIS_17_3_2 { Set-CISAuditPolicyForMode -Subcategory 'Process Creation' -Mode IncludeSuccess }

# ===================== 17.4 DS Access =====================

function Test-CIS_17_4_1 { Test-CISAuditPolicy -ControlId '17.4.1' -Title "Ensure 'Audit Directory Service Access' is set to include 'Failure' (DC only)" -Subcategory 'Directory Service Access' -Mode IncludeFailure -Scope DC }
function Set-CIS_17_4_1 { Set-CISAuditPolicyForMode -Subcategory 'Directory Service Access' -Mode IncludeFailure -Scope DC }

function Test-CIS_17_4_2 { Test-CISAuditPolicy -ControlId '17.4.2' -Title "Ensure 'Audit Directory Service Changes' is set to include 'Success' (DC only)" -Subcategory 'Directory Service Changes' -Mode IncludeSuccess -Scope DC }
function Set-CIS_17_4_2 { Set-CISAuditPolicyForMode -Subcategory 'Directory Service Changes' -Mode IncludeSuccess -Scope DC }

# ===================== 17.5 Logon/Logoff =====================

function Test-CIS_17_5_1 { Test-CISAuditPolicy -ControlId '17.5.1' -Title "Ensure 'Audit Account Lockout' is set to include 'Failure'" -Subcategory 'Account Lockout' -Mode IncludeFailure }
function Set-CIS_17_5_1 { Set-CISAuditPolicyForMode -Subcategory 'Account Lockout' -Mode IncludeFailure }

function Test-CIS_17_5_2 { Test-CISAuditPolicy -ControlId '17.5.2' -Title "Ensure 'Audit Group Membership' is set to include 'Success'" -Subcategory 'Group Membership' -Mode IncludeSuccess }
function Set-CIS_17_5_2 { Set-CISAuditPolicyForMode -Subcategory 'Group Membership' -Mode IncludeSuccess }

function Test-CIS_17_5_3 { Test-CISAuditPolicy -ControlId '17.5.3' -Title "Ensure 'Audit Logoff' is set to include 'Success'" -Subcategory 'Logoff' -Mode IncludeSuccess }
function Set-CIS_17_5_3 { Set-CISAuditPolicyForMode -Subcategory 'Logoff' -Mode IncludeSuccess }

function Test-CIS_17_5_4 { Test-CISAuditPolicy -ControlId '17.5.4' -Title "Ensure 'Audit Logon' is set to 'Success and Failure'" -Subcategory 'Logon' -Mode SuccessAndFailure }
function Set-CIS_17_5_4 { Set-CISAuditPolicyForMode -Subcategory 'Logon' -Mode SuccessAndFailure }

function Test-CIS_17_5_5 { Test-CISAuditPolicy -ControlId '17.5.5' -Title "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'" -Subcategory 'Other Logon/Logoff Events' -Mode SuccessAndFailure }
function Set-CIS_17_5_5 { Set-CISAuditPolicyForMode -Subcategory 'Other Logon/Logoff Events' -Mode SuccessAndFailure }

function Test-CIS_17_5_6 { Test-CISAuditPolicy -ControlId '17.5.6' -Title "Ensure 'Audit Special Logon' is set to include 'Success'" -Subcategory 'Special Logon' -Mode IncludeSuccess }
function Set-CIS_17_5_6 { Set-CISAuditPolicyForMode -Subcategory 'Special Logon' -Mode IncludeSuccess }

# ===================== 17.6 Object Access =====================

function Test-CIS_17_6_1 { Test-CISAuditPolicy -ControlId '17.6.1' -Title "Ensure 'Audit Detailed File Share' is set to include 'Failure'" -Subcategory 'Detailed File Share' -Mode IncludeFailure }
function Set-CIS_17_6_1 { Set-CISAuditPolicyForMode -Subcategory 'Detailed File Share' -Mode IncludeFailure }

function Test-CIS_17_6_2 { Test-CISAuditPolicy -ControlId '17.6.2' -Title "Ensure 'Audit File Share' is set to 'Success and Failure'" -Subcategory 'File Share' -Mode SuccessAndFailure }
function Set-CIS_17_6_2 { Set-CISAuditPolicyForMode -Subcategory 'File Share' -Mode SuccessAndFailure }

function Test-CIS_17_6_3 { Test-CISAuditPolicy -ControlId '17.6.3' -Title "Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'" -Subcategory 'Other Object Access Events' -Mode SuccessAndFailure }
function Set-CIS_17_6_3 { Set-CISAuditPolicyForMode -Subcategory 'Other Object Access Events' -Mode SuccessAndFailure }

function Test-CIS_17_6_4 { Test-CISAuditPolicy -ControlId '17.6.4' -Title "Ensure 'Audit Removable Storage' is set to 'Success and Failure'" -Subcategory 'Removable Storage' -Mode SuccessAndFailure }
function Set-CIS_17_6_4 { Set-CISAuditPolicyForMode -Subcategory 'Removable Storage' -Mode SuccessAndFailure }

# ===================== 17.7 Policy Change =====================

function Test-CIS_17_7_1 { Test-CISAuditPolicy -ControlId '17.7.1' -Title "Ensure 'Audit Audit Policy Change' is set to include 'Success'" -Subcategory 'Audit Policy Change' -Mode IncludeSuccess }
function Set-CIS_17_7_1 { Set-CISAuditPolicyForMode -Subcategory 'Audit Policy Change' -Mode IncludeSuccess }

function Test-CIS_17_7_2 { Test-CISAuditPolicy -ControlId '17.7.2' -Title "Ensure 'Audit Authentication Policy Change' is set to include 'Success'" -Subcategory 'Authentication Policy Change' -Mode IncludeSuccess }
function Set-CIS_17_7_2 { Set-CISAuditPolicyForMode -Subcategory 'Authentication Policy Change' -Mode IncludeSuccess }

function Test-CIS_17_7_3 { Test-CISAuditPolicy -ControlId '17.7.3' -Title "Ensure 'Audit Authorization Policy Change' is set to include 'Success'" -Subcategory 'Authorization Policy Change' -Mode IncludeSuccess }
function Set-CIS_17_7_3 { Set-CISAuditPolicyForMode -Subcategory 'Authorization Policy Change' -Mode IncludeSuccess }

function Test-CIS_17_7_4 { Test-CISAuditPolicy -ControlId '17.7.4' -Title "Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'" -Subcategory 'MPSSVC Rule-Level Policy Change' -Mode SuccessAndFailure }
function Set-CIS_17_7_4 { Set-CISAuditPolicyForMode -Subcategory 'MPSSVC Rule-Level Policy Change' -Mode SuccessAndFailure }

function Test-CIS_17_7_5 { Test-CISAuditPolicy -ControlId '17.7.5' -Title "Ensure 'Audit Other Policy Change Events' is set to include 'Failure'" -Subcategory 'Other Policy Change Events' -Mode IncludeFailure }
function Set-CIS_17_7_5 { Set-CISAuditPolicyForMode -Subcategory 'Other Policy Change Events' -Mode IncludeFailure }

# ===================== 17.8 Privilege Use =====================

function Test-CIS_17_8_1 { Test-CISAuditPolicy -ControlId '17.8.1' -Title "Ensure 'Audit Sensitive Privilege Use' is set to 'Success'" -Subcategory 'Sensitive Privilege Use' -Mode SuccessOnly }
function Set-CIS_17_8_1 { Set-CISAuditPolicyForMode -Subcategory 'Sensitive Privilege Use' -Mode SuccessOnly }

# ===================== 17.9 System =====================

function Test-CIS_17_9_1 { Test-CISAuditPolicy -ControlId '17.9.1' -Title "Ensure 'Audit IPsec Driver' is set to 'Success and Failure'" -Subcategory 'IPsec Driver' -Mode SuccessAndFailure }
function Set-CIS_17_9_1 { Set-CISAuditPolicyForMode -Subcategory 'IPsec Driver' -Mode SuccessAndFailure }

function Test-CIS_17_9_2 { Test-CISAuditPolicy -ControlId '17.9.2' -Title "Ensure 'Audit Other System Events' is set to 'Success and Failure'" -Subcategory 'Other System Events' -Mode SuccessAndFailure }
function Set-CIS_17_9_2 { Set-CISAuditPolicyForMode -Subcategory 'Other System Events' -Mode SuccessAndFailure }

function Test-CIS_17_9_3 { Test-CISAuditPolicy -ControlId '17.9.3' -Title "Ensure 'Audit Security State Change' is set to include 'Success'" -Subcategory 'Security State Change' -Mode IncludeSuccess }
function Set-CIS_17_9_3 { Set-CISAuditPolicyForMode -Subcategory 'Security State Change' -Mode IncludeSuccess }

function Test-CIS_17_9_4 { Test-CISAuditPolicy -ControlId '17.9.4' -Title "Ensure 'Audit Security System Extension' is set to include 'Success'" -Subcategory 'Security System Extension' -Mode IncludeSuccess }
function Set-CIS_17_9_4 { Set-CISAuditPolicyForMode -Subcategory 'Security System Extension' -Mode IncludeSuccess }

function Test-CIS_17_9_5 { Test-CISAuditPolicy -ControlId '17.9.5' -Title "Ensure 'Audit System Integrity' is set to 'Success and Failure'" -Subcategory 'System Integrity' -Mode SuccessAndFailure }
function Set-CIS_17_9_5 { Set-CISAuditPolicyForMode -Subcategory 'System Integrity' -Mode SuccessAndFailure }
