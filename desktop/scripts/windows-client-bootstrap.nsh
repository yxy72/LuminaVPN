; NSIS Unicode x86 host on native Windows x64. Only OS DLLs and the embedded
; service image are used. Every failure retains the installed application.
!ifndef LUMINA_PROTECTED_BOOTSTRAP_INCLUDED
!define LUMINA_PROTECTED_BOOTSTRAP_INCLUDED
!include "LogicLib.nsh"
!include "x64.nsh"
!ifndef NSIS_PTR_SIZE
  ; Older supported NSIS releases only emitted x86 installers.
  !define NSIS_PTR_SIZE 4
!endif
!if ${NSIS_PTR_SIZE} != 4
  !error "LuminaVPN protected setup requires the reviewed x86 NSIS host ABI"
!endif
!if ${NSIS_CHAR_SIZE} != 2
  !error "LuminaVPN protected setup requires Unicode NSIS"
!endif

Var LuminaFailure
Var LuminaSD
Var LuminaSA
Var LuminaSystemSID
Var LuminaAdminSID
Var LuminaTrustedInstallerSID
Var LuminaProgramData
Var LuminaSetupParent
Var LuminaNoncePath
Var LuminaNonce
Var LuminaProgramDataHandle
Var LuminaAncestorHandles
Var LuminaAncestorCount
Var LuminaAnchorHandle
Var LuminaAnchorPath
Var LuminaSetupHandle
Var LuminaNonceHandle
Var LuminaImageHandle
Var LuminaTrustHandle
Var LuminaCheckHandle
Var LuminaCheckStrict
Var LuminaCheckOK
Var LuminaCreated
Var LuminaExpires

!macro LuminaBootstrapFunctions P
Function ${P}LuminaCloseBootstrap
  System::Store "s"
  ${If} $LuminaImageHandle != 0
    System::Call '$SYSDIR\kernel32.dll::CloseHandle(p $LuminaImageHandle)'
    StrCpy $LuminaImageHandle 0
  ${EndIf}
  ${If} $LuminaTrustHandle != 0
    System::Call '$SYSDIR\kernel32.dll::CloseHandle(p $LuminaTrustHandle)'
    StrCpy $LuminaTrustHandle 0
  ${EndIf}
  ; The nonce directory was created exclusively with an explicit protected ACL.
  ; Delete only its two fixed files, never recurse or traverse another nonce.
  ${If} $LuminaNonceHandle != 0
  ${AndIf} $LuminaNoncePath != ""
    ${If} $PLUGINSDIR != ""
      SetOutPath $PLUGINSDIR
    ${EndIf}
    Delete "$LuminaNoncePath\lumina-service.exe"
    Delete "$LuminaNoncePath\bootstrap-trust.json"
    System::Call '$SYSDIR\kernel32.dll::CloseHandle(p $LuminaNonceHandle)'
    StrCpy $LuminaNonceHandle 0
    RMDir "$LuminaNoncePath"
  ${EndIf}
  ${If} $LuminaSetupHandle != 0
    System::Call '$SYSDIR\kernel32.dll::CloseHandle(p $LuminaSetupHandle)'
    StrCpy $LuminaSetupHandle 0
  ${EndIf}
  ${If} $LuminaProgramDataHandle != 0
    System::Call '$SYSDIR\kernel32.dll::CloseHandle(p $LuminaProgramDataHandle)'
    StrCpy $LuminaProgramDataHandle 0
  ${EndIf}
  ${If} $LuminaAncestorHandles != 0
    StrCpy $0 0
    StrCpy $1 $LuminaAncestorHandles
    ${DoWhile} $0 < $LuminaAncestorCount
      System::Call '*$1(p.r2)'
      System::Call '$SYSDIR\kernel32.dll::CloseHandle(p r2)'
      IntOp $1 $1 + 4
      IntOp $0 $0 + 1
    ${Loop}
    System::Free $LuminaAncestorHandles
    StrCpy $LuminaAncestorHandles 0
    StrCpy $LuminaAncestorCount 0
  ${EndIf}
  ${If} $LuminaAnchorHandle != 0
    System::Call '$SYSDIR\kernel32.dll::CloseHandle(p $LuminaAnchorHandle)'
    StrCpy $LuminaAnchorHandle 0
  ${EndIf}
  ${If} $LuminaSA != 0
    System::Free $LuminaSA
    StrCpy $LuminaSA 0
  ${EndIf}
  ${If} $LuminaSD != 0
    System::Call '$SYSDIR\kernel32.dll::LocalFree(p $LuminaSD)'
    StrCpy $LuminaSD 0
  ${EndIf}
  ${If} $LuminaSystemSID != 0
    System::Call '$SYSDIR\kernel32.dll::LocalFree(p $LuminaSystemSID)'
    StrCpy $LuminaSystemSID 0
  ${EndIf}
  ${If} $LuminaAdminSID != 0
    System::Call '$SYSDIR\kernel32.dll::LocalFree(p $LuminaAdminSID)'
    StrCpy $LuminaAdminSID 0
  ${EndIf}
  ${If} $LuminaTrustedInstallerSID != 0
    System::Free $LuminaTrustedInstallerSID
    StrCpy $LuminaTrustedInstallerSID 0
  ${EndIf}
  System::Store "l"
FunctionEnd

Function ${P}LuminaBootstrapFatal
  Call ${P}LuminaCloseBootstrap
  DetailPrint "LuminaVPN protected setup failed ($LuminaFailure). Installed files were retained."
  SetErrorLevel 2
  Quit
FunctionEnd

; Check the exact opened object, including owner and all effective allow ACEs.
; A strict setup object permits writes only to Administrators and SYSTEM.
; ProgramData may permit creating new children, but not deleting existing ones
; or changing its ACL/owner. Its handle denies WRITE/DELETE sharing meanwhile.
Function ${P}LuminaCheckProtected
  System::Store "s"
  StrCpy $LuminaCheckOK 0
  System::Call '$SYSDIR\advapi32.dll::GetSecurityInfo(p $LuminaCheckHandle, i 1, i 5, *p .r0, p 0, *p .r1, p 0, *p .r2)i.r3'
  ${If} $3 != 0
    Goto check_done
  ${EndIf}
  ${If} $0 == 0
  ${OrIf} $1 == 0
  ${OrIf} $2 == 0
    Goto check_free
  ${EndIf}
  System::Call '$SYSDIR\advapi32.dll::EqualSid(p r0, p $LuminaSystemSID)i.r3'
  System::Call '$SYSDIR\advapi32.dll::EqualSid(p r0, p $LuminaAdminSID)i.r4'
  IntOp $3 $3 | $4
  ${If} $LuminaCheckStrict == 0
    System::Call '$SYSDIR\advapi32.dll::EqualSid(p r0, p $LuminaTrustedInstallerSID)i.r4'
    IntOp $3 $3 | $4
  ${EndIf}
  ${If} $3 == 0
    Goto check_free
  ${EndIf}
  System::Call '$SYSDIR\advapi32.dll::GetSecurityDescriptorControl(p r2, *i 0 r3, *i .r4)i.r5'
  ${If} $5 == 0
    Goto check_free
  ${EndIf}
  ${If} $LuminaCheckStrict == 1
    IntOp $3 $3 & 0x1000
    ${If} $3 == 0
      Goto check_free
    ${EndIf}
  ${EndIf}
  System::Call '$SYSDIR\advapi32.dll::IsValidAcl(p r1)i.r3'
  ${If} $3 == 0
    Goto check_free
  ${EndIf}
  System::Call '*(i 0, i 0, i 0)p.r4'
  System::Call '$SYSDIR\advapi32.dll::GetAclInformation(p r1, p r4, i 12, i 2)i.r3'
  ${If} $3 == 0
    System::Free $4
    Goto check_free
  ${EndIf}
  System::Call '*$4(i.r6, i.r7, i.r8)'
  System::Free $4
  ${If} $6 > 128
  ${OrIf} $7 > 65535
  ${OrIf} $7 < 8
    Goto check_free
  ${EndIf}
  StrCpy $9 0
  acl_loop:
    ${If} $9 >= $6
      StrCpy $LuminaCheckOK 1
      Goto check_free
    ${EndIf}
    System::Call '$SYSDIR\advapi32.dll::GetAce(p r1, i r9, *p .r4)i.r3'
    ${If} $3 == 0
      Goto check_free
    ${EndIf}
    System::Call '*$4(&i1.r3, &i1.r5, &i2.r7)'
    IntOp $5 $5 & 8 ; INHERIT_ONLY_ACE does not apply to this opened object.
    ${If} $5 != 0
      Goto acl_next
    ${EndIf}
    ${If} $3 == 1 ; Standard deny ACEs can only reduce access.
      Goto acl_next
    ${EndIf}
    ${If} $3 != 0 ; Object/callback/unknown ACEs are not interpreted as safe.
    ${OrIf} $7 < 12
      Goto check_free
    ${EndIf}
    System::Call '*$4(i, i.r7)'
    IntOp $4 $4 + 8
    System::Call '$SYSDIR\advapi32.dll::IsValidSid(p r4)i.r3'
    ${If} $3 == 0
      Goto check_free
    ${EndIf}
    System::Call '$SYSDIR\advapi32.dll::EqualSid(p r4, p $LuminaSystemSID)i.r3'
    System::Call '$SYSDIR\advapi32.dll::EqualSid(p r4, p $LuminaAdminSID)i.r5'
    IntOp $3 $3 | $5
    ${If} $LuminaCheckStrict == 0
      System::Call '$SYSDIR\advapi32.dll::EqualSid(p r4, p $LuminaTrustedInstallerSID)i.r5'
      IntOp $3 $3 | $5
    ${EndIf}
    ${If} $3 == 0
      ${If} $LuminaCheckStrict == 1
        ; GENERIC_ALL/WRITE; DELETE/WRITE_DAC/OWNER; data/EA/attrs/DELETE_CHILD.
        IntOp $7 $7 & 0x500D0156
      ${Else}
        ; Match Go ancestorReplaceMask: new children/EA/attributes do not
        ; authorize deleting this child or replacing its security. The held
        ; held data-read handles deny DELETE sharing. Path binding and the
        ; pinned existing child make every ancestor stably nonempty before use.
        IntOp $7 $7 & 0x100D0040
      ${EndIf}
      ${If} $7 != 0
        Goto check_free
      ${EndIf}
    ${EndIf}
    acl_next:
    IntOp $9 $9 + 1
    Goto acl_loop
  check_free:
    System::Call '$SYSDIR\kernel32.dll::LocalFree(p r2)'
  check_done:
  System::Store "l"
FunctionEnd

; $0 is a directory path. The returned handle in $LuminaCheckHandle stays open
; without sharing WRITE or DELETE; metadata is queried from that same handle.
Function ${P}LuminaOpenDirectory
  System::Store "p1 p2 p3 p4 p5"
  StrCpy $LuminaCheckHandle 0
  System::Call '$SYSDIR\kernel32.dll::CreateFileW(w r0, i 0x120081, i 1, p 0, i 3, i 0x02200000, p 0)p.r1'
  ${If} $1 == -1
    StrCpy $LuminaFailure "OPEN_DIRECTORY"
    Goto directory_done
  ${EndIf}
  System::Call '*(i 0, i 0)p.r2'
  System::Call '$SYSDIR\kernel32.dll::GetFileInformationByHandleEx(p r1, i 9, p r2, i 8)i.r3'
  ${If} $3 != 0
    System::Call '*$2(i.r3, i)'
    IntOp $3 $3 & 0x410 ; FILE_ATTRIBUTE_REPARSE_POINT | DIRECTORY.
    ${If} $3 = 0x10
      ; A transient junction in a parent must not bind this handle to some
      ; other existing trusted directory. Compare normalized DOS final paths.
      System::Call '$SYSDIR\kernel32.dll::GetFinalPathNameByHandleW(p r1, w .r4, i ${NSIS_MAX_STRLEN}, i 0)i.r3'
      StrCpy $5 "\\?\$0"
      ${If} $3 > 0
      ${AndIf} $3 < ${NSIS_MAX_STRLEN}
      ${AndIf} $4 == $5 ; NSIS StrCmp compares Windows paths case-insensitively.
        StrCpy $LuminaCheckHandle $1
      ${EndIf}
    ${EndIf}
  ${EndIf}
  System::Free $2
  ${If} $LuminaCheckHandle == 0
    System::Call '$SYSDIR\kernel32.dll::CloseHandle(p r1)'
    StrCpy $LuminaFailure "DIRECTORY_REPARSE_OR_QUERY"
  ${EndIf}
  directory_done:
  System::Store "r5 r4 r3 r2 r1"
FunctionEnd

; Called only after the full path-bound chain and its existing terminal child
; are pinned. No ancestor can then become empty or be renamed by another open.
Function ${P}LuminaCheckPinnedDirectory
  System::Store "s"
  StrCpy $LuminaCheckOK 0
  System::Call '*(i 0, i 0)p.r0'
  System::Call '$SYSDIR\kernel32.dll::GetFileInformationByHandleEx(p $LuminaCheckHandle, i 9, p r0, i 8)i.r1'
  ${If} $1 != 0
    System::Call '*$0(i.r1, i)'
    IntOp $1 $1 & 0x410
    ${If} $1 = 0x10
      StrCpy $LuminaCheckOK 1
    ${EndIf}
  ${EndIf}
  System::Free $0
  System::Store "l"
FunctionEnd

; Create an exclusive new file using the same explicit protected descriptor.
; $0=destination, return=$1. The writer is closed before strict read locking.
Function ${P}LuminaCreateFile
  System::Call '$SYSDIR\kernel32.dll::CreateFileW(w r0, i 0xC0000000, i 0, p $LuminaSA, i 1, i 0x00200080, p 0)p.r1'
FunctionEnd

Function ${P}LuminaCheckRegular
  System::Store "s"
  StrCpy $LuminaCheckOK 0
  System::Call '*(i 0, i 0)p.r0'
  System::Call '$SYSDIR\kernel32.dll::GetFileInformationByHandleEx(p $LuminaCheckHandle, i 9, p r0, i 8)i.r1'
  ${If} $1 != 0
    System::Call '*$0(i.r1, i)'
    IntOp $1 $1 & 0x410
    ${If} $1 == 0
      StrCpy $LuminaCheckOK 1
    ${EndIf}
  ${EndIf}
  System::Free $0
  System::Store "l"
FunctionEnd

; Copy the embedded data to CREATE_NEW, never execute $PLUGINSDIR content.
Function ${P}LuminaCopyImage
  System::Store "s"
  StrCpy $0 "$LuminaNoncePath\lumina-service.exe"
  Call ${P}LuminaCreateFile
  ${If} $1 == -1
    StrCpy $LuminaFailure "CREATE_IMAGE"
    Goto copy_done
  ${EndIf}
  StrCpy $R1 $1
  System::Call '$SYSDIR\kernel32.dll::CreateFileW(w "$PLUGINSDIR\lumina-bootstrap.bin", i 0x80000000, i 1, p 0, i 3, i 0x00200080, p 0)p.r2'
  ${If} $2 == -1
    StrCpy $LuminaFailure "OPEN_EMBEDDED_DATA"
    Goto copy_close_writer
  ${EndIf}
  StrCpy $R2 $2
  System::Alloc 65536
  Pop $R3
  StrCpy $R4 0
  copy_loop:
    System::Call '$SYSDIR\kernel32.dll::ReadFile(p $R2, p $R3, i 65536, *i .r3, p 0)i.r4'
    ${If} $4 == 0
    ${OrIf} $3 > 65536
      StrCpy $LuminaFailure "READ_EMBEDDED_DATA"
      Goto copy_free
    ${EndIf}
    ${If} $3 == 0
      ${If} $R4 == 0
        StrCpy $LuminaFailure "EMPTY_IMAGE"
      ${EndIf}
      Goto copy_free
    ${EndIf}
    IntOp $R4 $R4 + $3
    ${If} $R4 > 67108864
      StrCpy $LuminaFailure "IMAGE_SIZE"
      Goto copy_free
    ${EndIf}
    System::Call '$SYSDIR\kernel32.dll::WriteFile(p $R1, p $R3, i r3, *i .r5, p 0)i.r4'
    ${If} $4 == 0
    ${OrIf} $5 != $3
      StrCpy $LuminaFailure "WRITE_IMAGE"
      Goto copy_free
    ${EndIf}
    Goto copy_loop
  copy_free:
  System::Free $R3
  System::Call '$SYSDIR\kernel32.dll::CloseHandle(p $R2)'
  copy_close_writer:
  System::Call '$SYSDIR\kernel32.dll::FlushFileBuffers(p $R1)i.r4'
  ${If} $4 == 0
    StrCpy $LuminaFailure "FLUSH_IMAGE"
  ${EndIf}
  System::Call '$SYSDIR\kernel32.dll::CloseHandle(p $R1)'
  copy_done:
  System::Store "l"
FunctionEnd

Function ${P}LuminaLockAndHashImage
  System::Store "s"
  System::Call '$SYSDIR\kernel32.dll::CreateFileW(w "$LuminaNoncePath\lumina-service.exe", i 0x80020000, i 1, p 0, i 3, i 0x00200080, p 0)p.r0'
  ${If} $0 == -1
    StrCpy $LuminaFailure "LOCK_IMAGE"
    Goto hash_done
  ${EndIf}
  StrCpy $LuminaImageHandle $0
  StrCpy $LuminaCheckHandle $0
  Call ${P}LuminaCheckRegular
  ${If} $LuminaCheckOK != 1
    StrCpy $LuminaFailure "IMAGE_REPARSE_OR_DIRECTORY"
    Goto hash_done
  ${EndIf}
  StrCpy $LuminaCheckStrict 1
  Call ${P}LuminaCheckProtected
  ${If} $LuminaCheckOK != 1
    StrCpy $LuminaFailure "IMAGE_ACL"
    Goto hash_done
  ${EndIf}
  System::Call '$SYSDIR\bcrypt.dll::BCryptOpenAlgorithmProvider(*p .r1, w "SHA256", p 0, i 0)i.r0'
  ${If} $0 != 0
    StrCpy $LuminaFailure "HASH_PROVIDER"
    Goto hash_done
  ${EndIf}
  ; Win7+ can allocate the hash object internally, avoiding object-size ABI assumptions.
  System::Call '$SYSDIR\bcrypt.dll::BCryptCreateHash(p r1, *p .r2, p 0, i 0, p 0, i 0, i 0)i.r0'
  ${If} $0 != 0
    StrCpy $LuminaFailure "HASH_CREATE"
    Goto hash_close_provider
  ${EndIf}
  System::Alloc 65536
  Pop $R0
  hash_loop:
    System::Call '$SYSDIR\kernel32.dll::ReadFile(p $LuminaImageHandle, p $R0, i 65536, *i .r3, p 0)i.r4'
    ${If} $4 == 0
    ${OrIf} $3 > 65536
      StrCpy $LuminaFailure "HASH_READ"
      Goto hash_free
    ${EndIf}
    ${If} $3 == 0
      Goto hash_finish
    ${EndIf}
    System::Call '$SYSDIR\bcrypt.dll::BCryptHashData(p r2, p $R0, i r3, i 0)i.r4'
    ${If} $4 != 0
      StrCpy $LuminaFailure "HASH_UPDATE"
      Goto hash_free
    ${EndIf}
    Goto hash_loop
  hash_finish:
    System::Call '$SYSDIR\bcrypt.dll::BCryptFinishHash(p r2, p $R0, i 32, i 0)i.r4'
    ${If} $4 != 0
      StrCpy $LuminaFailure "HASH_FINISH"
      Goto hash_free
    ${EndIf}
    StrCpy $5 ""
    StrCpy $6 0
    StrCpy $7 $R0
    hash_hex:
      System::Call '*$7(&i1.r8)'
      IntOp $8 $8 & 255
      IntFmt $8 "%02x" $8
      StrCpy $5 "$5$8"
      IntOp $7 $7 + 1
      IntOp $6 $6 + 1
      ${If} $6 < 32
        Goto hash_hex
      ${EndIf}
    ${If} $5 != "${LUMINA_BOOTSTRAP_SHA256}"
      StrCpy $LuminaFailure "HASH_MISMATCH"
    ${EndIf}
  hash_free:
  System::Free $R0
  System::Call '$SYSDIR\bcrypt.dll::BCryptDestroyHash(p r2)'
  hash_close_provider:
  System::Call '$SYSDIR\bcrypt.dll::BCryptCloseAlgorithmProvider(p r1, i 0)'
  hash_done:
  System::Store "l"
FunctionEnd

Function ${P}LuminaPrepareBootstrap
  System::Store "s"
  StrCpy $LuminaFailure ""
  StrCpy $LuminaSD 0
  StrCpy $LuminaSA 0
  StrCpy $LuminaSystemSID 0
  StrCpy $LuminaAdminSID 0
  StrCpy $LuminaTrustedInstallerSID 0
  StrCpy $LuminaProgramDataHandle 0
  StrCpy $LuminaAncestorHandles 0
  StrCpy $LuminaAncestorCount 0
  StrCpy $LuminaAnchorHandle 0
  StrCpy $LuminaAnchorPath ""
  StrCpy $LuminaSetupHandle 0
  StrCpy $LuminaNonceHandle 0
  StrCpy $LuminaImageHandle 0
  StrCpy $LuminaTrustHandle 0
  StrCpy $LuminaNoncePath ""
  ; All structure pointers use the NSIS host ABI (Unicode x86), not the x64 target ABI.
  System::Call '$SYSDIR\advapi32.dll::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", i 1, *p .r0, p 0)i.r1'
  ${If} $1 == 0
    StrCpy $LuminaFailure "SECURITY_DESCRIPTOR"
    Goto prepare_done
  ${EndIf}
  StrCpy $LuminaSD $0
  System::Call '*(i 12, p $LuminaSD, i 0)p.r0'
  StrCpy $LuminaSA $0
  System::Call '$SYSDIR\advapi32.dll::ConvertStringSidToSidW(w "S-1-5-18", *p .r0)i.r1'
  ${If} $1 == 0
    StrCpy $LuminaFailure "SYSTEM_SID"
    Goto prepare_done
  ${EndIf}
  StrCpy $LuminaSystemSID $0
  System::Call '$SYSDIR\advapi32.dll::ConvertStringSidToSidW(w "S-1-5-32-544", *p .r0)i.r1'
  ${If} $1 == 0
    StrCpy $LuminaFailure "ADMIN_SID"
    Goto prepare_done
  ${EndIf}
  StrCpy $LuminaAdminSID $0
  ; Existing OS ancestors may be owned or maintained by TrustedInstaller.
  ; Resolve only that fixed local service identity through Windows; strict
  ; setup directories and executable files still permit only SYSTEM/Admins.
  System::Alloc 68 ; SECURITY_MAX_SID_SIZE, including every possible subauthority.
  Pop $LuminaTrustedInstallerSID
  ${If} $LuminaTrustedInstallerSID == 0
    StrCpy $LuminaFailure "TRUSTED_INSTALLER_MEMORY"
    Goto prepare_done
  ${EndIf}
  System::Alloc 512 ; Bounded 256-WCHAR referenced-domain buffer.
  Pop $5
  ${If} $5 == 0
    StrCpy $LuminaFailure "TRUSTED_INSTALLER_MEMORY"
    Goto prepare_done
  ${EndIf}
  System::Call '$SYSDIR\advapi32.dll::LookupAccountNameW(p 0, w "NT SERVICE\TrustedInstaller", p $LuminaTrustedInstallerSID, *i 68 r1, p r5, *i 256 r2, *i .r3)i.r0'
  System::Free $5
  ${If} $0 == 0
  ${OrIf} $1 < 8
  ${OrIf} $1 > 68
    StrCpy $LuminaFailure "TRUSTED_INSTALLER_SID"
    Goto prepare_done
  ${EndIf}
  System::Call '$SYSDIR\advapi32.dll::IsValidSid(p $LuminaTrustedInstallerSID)i.r0'
  ${If} $0 == 0
    StrCpy $LuminaFailure "TRUSTED_INSTALLER_SID"
    Goto prepare_done
  ${EndIf}
  System::Call '$SYSDIR\advapi32.dll::GetLengthSid(p $LuminaTrustedInstallerSID)i.r0'
  ${If} $0 < 8
  ${OrIf} $0 > 68
    StrCpy $LuminaFailure "TRUSTED_INSTALLER_SID"
    Goto prepare_done
  ${EndIf}
  System::Call '$SYSDIR\shell32.dll::SHGetKnownFolderPath(g "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}", i 0, p 0, *p .r0)i.r1'
  ${If} $1 != 0
    StrCpy $LuminaFailure "PROGRAMDATA"
    Goto prepare_done
  ${EndIf}
  System::Call '*$0(&w${NSIS_MAX_STRLEN}.r1)'
  System::Call '$SYSDIR\ole32.dll::CoTaskMemFree(p r0)'
  StrCpy $LuminaProgramData $1
  StrLen $0 $LuminaProgramData
  ${If} $0 > 160
  ${OrIf} $0 < 4
    StrCpy $LuminaFailure "PROGRAMDATA_LENGTH"
    Goto prepare_done
  ${EndIf}
  ; Walk from the local fixed drive root, opening each component itself rather
  ; than following an intermediate junction through a final-component check.
  StrCpy $0 $LuminaProgramData 1 1
  StrCpy $1 $LuminaProgramData 1 2
  ${If} $0 != ":"
  ${OrIf} $1 != "\"
    StrCpy $LuminaFailure "PROGRAMDATA_LOCAL_PATH"
    Goto prepare_done
  ${EndIf}
  StrCpy $R5 $LuminaProgramData 3
  System::Call '$SYSDIR\kernel32.dll::GetDriveTypeW(w "$R5")i.r0'
  ${If} $0 != 3
    StrCpy $LuminaFailure "PROGRAMDATA_FIXED_DRIVE"
    Goto prepare_done
  ${EndIf}
  System::Alloc 128
  Pop $LuminaAncestorHandles
  ${If} $LuminaAncestorHandles == 0
    StrCpy $LuminaFailure "ANCESTOR_MEMORY"
    Goto prepare_done
  ${EndIf}
  StrCpy $LuminaAncestorCount 0
  StrCpy $R6 3
  StrLen $R7 $LuminaProgramData
  ancestor_open:
    StrCpy $0 $R5
    Call ${P}LuminaOpenDirectory
    ${If} $LuminaCheckHandle == 0
      Goto prepare_done
    ${EndIf}
    ${If} $R6 > $R7
      StrCpy $LuminaProgramDataHandle $LuminaCheckHandle
    ${Else}
      ${If} $LuminaAncestorCount >= 32
        System::Call '$SYSDIR\kernel32.dll::CloseHandle(p $LuminaCheckHandle)'
        StrCpy $LuminaFailure "PROGRAMDATA_DEPTH"
        Goto prepare_done
      ${EndIf}
      IntOp $0 $LuminaAncestorCount * 4
      IntOp $0 $LuminaAncestorHandles + $0
      System::Call '*$0(p $LuminaCheckHandle)'
      IntOp $LuminaAncestorCount $LuminaAncestorCount + 1
    ${EndIf}
    StrCpy $LuminaCheckStrict 0
    Call ${P}LuminaCheckProtected
    ${If} $LuminaCheckOK != 1
      StrCpy $LuminaFailure "PROGRAMDATA_ANCESTOR_ACL"
      Goto prepare_done
    ${EndIf}
    ${If} $R6 > $R7
      Goto ancestors_ready
    ${EndIf}
    StrCpy $R8 ""
    ancestor_component:
      ${If} $R6 >= $R7
        IntOp $R6 $R7 + 1
        Goto ancestor_component_ready
      ${EndIf}
      StrCpy $0 $LuminaProgramData 1 $R6
      IntOp $R6 $R6 + 1
      ${If} $0 == "\"
        Goto ancestor_component_ready
      ${EndIf}
      StrCpy $R8 "$R8$0"
      Goto ancestor_component
    ancestor_component_ready:
      ${If} $R8 == ""
      ${OrIf} $R8 == "."
      ${OrIf} $R8 == ".."
        StrCpy $LuminaFailure "PROGRAMDATA_COMPONENT"
        Goto prepare_done
      ${EndIf}
      StrCpy $0 $R5 1 -1
      ${If} $0 != "\"
        StrCpy $R5 "$R5\"
      ${EndIf}
      StrCpy $R5 "$R5$R8"
      Goto ancestor_open
  ancestors_ready:
  StrCpy $LuminaSetupParent "$LuminaProgramData\LuminaVPN-Setup"
  ; Attribute-only access is not denied by sharing flags. FSCTL reparse
  ; assignment does reject nonempty directories, so pin an existing protected
  ; child before creating anything. A standard Windows ProgramData has Microsoft.
  StrCpy $LuminaAnchorPath $LuminaSetupParent
  System::Call '$SYSDIR\kernel32.dll::GetFileAttributesW(w "$LuminaAnchorPath")i.r0 ?e'
  Pop $1
  ${If} $0 == -1
    ${If} $1 == 2
    ${OrIf} $1 == 3
      StrCpy $LuminaAnchorPath "$LuminaProgramData\Microsoft"
    ${Else}
      StrCpy $LuminaFailure "PROGRAMDATA_ANCHOR_QUERY"
      Goto prepare_done
    ${EndIf}
  ${EndIf}
  StrCpy $0 $LuminaAnchorPath
  Call ${P}LuminaOpenDirectory
  StrCpy $LuminaAnchorHandle $LuminaCheckHandle
  ${If} $LuminaAnchorHandle == 0
    StrCpy $LuminaFailure "PROGRAMDATA_ANCHOR_OPEN"
    Goto prepare_done
  ${EndIf}
  StrCpy $LuminaCheckStrict 0
  Call ${P}LuminaCheckProtected
  ${If} $LuminaCheckOK != 1
    StrCpy $LuminaFailure "PROGRAMDATA_ANCHOR_ACL"
    Goto prepare_done
  ${EndIf}
  StrCpy $4 0
  StrCpy $5 $LuminaAncestorHandles
  ${DoWhile} $4 < $LuminaAncestorCount
    System::Call '*$5(p.r0)'
    StrCpy $LuminaCheckHandle $0
    Call ${P}LuminaCheckPinnedDirectory
    ${If} $LuminaCheckOK != 1
      StrCpy $LuminaFailure "PROGRAMDATA_ANCESTOR_CHANGED"
      Goto prepare_done
    ${EndIf}
    IntOp $5 $5 + 4
    IntOp $4 $4 + 1
  ${Loop}
  StrCpy $LuminaCheckHandle $LuminaProgramDataHandle
  Call ${P}LuminaCheckPinnedDirectory
  ${If} $LuminaCheckOK != 1
    StrCpy $LuminaFailure "PROGRAMDATA_CHANGED"
    Goto prepare_done
  ${EndIf}
  StrCpy $LuminaCheckHandle $LuminaAnchorHandle
  Call ${P}LuminaCheckPinnedDirectory
  ${If} $LuminaCheckOK != 1
    StrCpy $LuminaFailure "PROGRAMDATA_ANCHOR_CHANGED"
    Goto prepare_done
  ${EndIf}
  System::Call '$SYSDIR\kernel32.dll::CreateDirectoryW(w "$LuminaSetupParent", p $LuminaSA)i.r0 ?e'
  Pop $1
  ${If} $0 == 0
  ${AndIf} $1 != 183
    StrCpy $LuminaFailure "SETUP_PARENT_CREATE"
    Goto prepare_done
  ${EndIf}
  StrCpy $0 $LuminaSetupParent
  Call ${P}LuminaOpenDirectory
  StrCpy $LuminaSetupHandle $LuminaCheckHandle
  ${If} $LuminaSetupHandle == 0
    Goto prepare_done
  ${EndIf}
  StrCpy $LuminaCheckStrict 1
  Call ${P}LuminaCheckProtected
  ${If} $LuminaCheckOK != 1
    StrCpy $LuminaFailure "SETUP_PARENT_ACL"
    Goto prepare_done
  ${EndIf}
  System::Alloc 16
  Pop $R0
  System::Call '$SYSDIR\bcrypt.dll::BCryptGenRandom(p 0, p $R0, i 16, i 2)i.r0'
  ${If} $0 != 0
    System::Free $R0
    StrCpy $LuminaFailure "NONCE_RANDOM"
    Goto prepare_done
  ${EndIf}
  StrCpy $LuminaNonce ""
  StrCpy $0 0
  StrCpy $1 $R0
  nonce_loop:
    System::Call '*$1(&i1.r2)'
    IntOp $2 $2 & 255
    IntFmt $2 "%02x" $2
    StrCpy $LuminaNonce "$LuminaNonce$2"
    IntOp $1 $1 + 1
    IntOp $0 $0 + 1
    ${If} $0 < 16
      Goto nonce_loop
    ${EndIf}
  System::Free $R0
  StrCpy $LuminaNoncePath "$LuminaSetupParent\$LuminaNonce"
  System::Call '$SYSDIR\kernel32.dll::CreateDirectoryW(w "$LuminaNoncePath", p $LuminaSA)i.r0'
  ${If} $0 == 0 ; Never reuse or repair a colliding nonce directory.
    StrCpy $LuminaFailure "NONCE_CREATE"
    Goto prepare_done
  ${EndIf}
  StrCpy $0 $LuminaNoncePath
  Call ${P}LuminaOpenDirectory
  StrCpy $LuminaNonceHandle $LuminaCheckHandle
  ${If} $LuminaNonceHandle == 0
    Goto prepare_done
  ${EndIf}
  StrCpy $LuminaCheckStrict 1
  Call ${P}LuminaCheckProtected
  ${If} $LuminaCheckOK != 1
    StrCpy $LuminaFailure "NONCE_ACL"
    Goto prepare_done
  ${EndIf}
  InitPluginsDir
  SetOutPath $PLUGINSDIR
  ClearErrors
  File /oname=lumina-bootstrap.bin "${LUMINA_BOOTSTRAP_SOURCE}"
  ${If} ${Errors}
    StrCpy $LuminaFailure "EXTRACT_EMBEDDED_DATA"
    Goto prepare_done
  ${EndIf}
  Call ${P}LuminaCopyImage
  ${If} $LuminaFailure != ""
    Goto prepare_done
  ${EndIf}
  Call ${P}LuminaLockAndHashImage
  ${If} $LuminaFailure != ""
    Goto prepare_done
  ${EndIf}
  System::Call '$SYSDIR\kernel32.dll::GetSystemTimeAsFileTime(*l .r0)'
  System::Int64Op $0 / 10000000
  Pop $0
  System::Int64Op $0 - 11644473600
  Pop $LuminaCreated
  System::Int64Op $LuminaCreated + 1800
  Pop $LuminaExpires
  StrCpy $0 "$LuminaNoncePath\bootstrap-trust.json"
  Call ${P}LuminaCreateFile
  ${If} $1 == -1
    StrCpy $LuminaFailure "CREATE_TRUST"
    Goto prepare_done
  ${EndIf}
  StrCpy $R0 $1
  StrCpy $2 '{$\"version$\":1,$\"product$\":$\"LuminaVPN$\",$\"purpose$\":$\"service-bootstrap$\",$\"nonce$\":$\"$LuminaNonce$\",$\"sha256$\":$\"${LUMINA_BOOTSTRAP_SHA256}$\",$\"created_unix$\":$LuminaCreated,$\"expires_unix$\":$LuminaExpires}'
  StrLen $3 $2 ; All JSON characters are ASCII; byte length equals character count.
  System::Call '$SYSDIR\kernel32.dll::WriteFile(p $R0, m r2, i r3, *i .r4, p 0)i.r5'
  ${If} $5 == 0
  ${OrIf} $4 != $3
    StrCpy $LuminaFailure "WRITE_TRUST"
  ${EndIf}
  System::Call '$SYSDIR\kernel32.dll::FlushFileBuffers(p $R0)i.r5'
  ${If} $5 == 0
    StrCpy $LuminaFailure "FLUSH_TRUST"
  ${EndIf}
  System::Call '$SYSDIR\kernel32.dll::CloseHandle(p $R0)'
  ${If} $LuminaFailure != ""
    Goto prepare_done
  ${EndIf}
  System::Call '$SYSDIR\kernel32.dll::CreateFileW(w "$LuminaNoncePath\bootstrap-trust.json", i 0x80020000, i 1, p 0, i 3, i 0x00200080, p 0)p.r0'
  ${If} $0 == -1
    StrCpy $LuminaFailure "LOCK_TRUST"
    Goto prepare_done
  ${EndIf}
  StrCpy $LuminaTrustHandle $0
  StrCpy $LuminaCheckHandle $0
  Call ${P}LuminaCheckRegular
  ${If} $LuminaCheckOK != 1
    StrCpy $LuminaFailure "TRUST_REPARSE_OR_DIRECTORY"
    Goto prepare_done
  ${EndIf}
  StrCpy $LuminaCheckStrict 1
  Call ${P}LuminaCheckProtected
  ${If} $LuminaCheckOK != 1
    StrCpy $LuminaFailure "TRUST_ACL"
  ${EndIf}
  ${If} $LuminaFailure == ""
    ; The executed image must not use the untrusted extraction directory as CWD.
    SetOutPath $LuminaNoncePath
  ${EndIf}
  prepare_done:
  System::Store "l"
  ${If} $LuminaFailure != ""
    Call ${P}LuminaBootstrapFatal
  ${EndIf}
FunctionEnd
!macroend

!ifdef BUILD_UNINSTALLER
  !insertmacro LuminaBootstrapFunctions "un."
!else
  !insertmacro LuminaBootstrapFunctions ""
!endif
!endif
