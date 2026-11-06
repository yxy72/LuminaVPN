import {describe,it,expect} from 'vitest'
import {installedRecoveryScript} from '../src/main/recovery-entry'
describe('fixed installed recovery entry',()=>{
 it('reveals a fixed recover command without any renderer-supplied runtime/profile/nonce',()=>{
  const script=installedRecoveryScript({entry_kind:'installed_service_recover',image:'C:\\Program Files\\LuminaVPN\\lumina-service.exe',arguments:['--recover']})
  const encoded=script.match(/-EncodedCommand ([A-Za-z0-9+/=]+)/)![1],command=Buffer.from(encoded,'base64').toString('utf16le')
  expect(command).toContain("'C:\\Program Files\\LuminaVPN\\lumina-service.exe' --recover")
  expect(command).not.toContain('--profile');expect(command).not.toContain('--runtime')
 })
 it('rejects arbitrary command arguments and untrusted relative images',()=>{
  expect(()=>installedRecoveryScript({entry_kind:'installed_service_recover',image:'relative.exe',arguments:['--recover']})).toThrow()
  expect(()=>installedRecoveryScript({entry_kind:'installed_service_recover',image:'C:\\fixed.exe',arguments:['--recover','--profile','private']})).toThrow()
 })
})
