import {win32} from 'node:path'
import {isRecord} from '../../protocol/validation-base'

// Input comes only from the trusted Go installed-catalog loader. The renderer
// supplies no image, arguments, profile path or recovery nonce.
export function installedRecoveryScript(entry:unknown):string {
  if(!isRecord(entry)||entry.entry_kind!=='installed_service_recover'||typeof entry.image!=='string'||!win32.isAbsolute(entry.image)||!Array.isArray(entry.arguments)||entry.arguments.length!==1||entry.arguments[0]!=='--recover')throw new Error('RECOVERY_UNAVAILABLE')
  const quote=(value:string)=>"'"+value.replaceAll("'","''")+"'"
  const command='& '+quote(entry.image)+' --recover; exit $LASTEXITCODE'
  const encoded=Buffer.from(command,'utf16le').toString('base64')
  return '@echo off\r\nsetlocal DisableDelayedExpansion\r\npowershell.exe -NoProfile -EncodedCommand '+encoded+'\r\nset "lumina_exit=%errorlevel%"\r\npause\r\nexit /b %lumina_exit%\r\n'
}
