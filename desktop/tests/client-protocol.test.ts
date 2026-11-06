import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { CLIENT_METHODS, validateClientRequest, validateClientResult } from '../protocol/client'
import { validateRequest, validateResult } from '../protocol/validation'
import { READ_METHODS } from '../protocol/types'

const envelope = { request_id:'request', profile_id:'profile', expected_revision:0 }
const operation = { operation_id:'operation',request_id:'request',profile_id:'profile',revision:0,kind:'exit_restore',phase:'completed',completed:true,restored:true,created_at:'2026-11-06T00:00:00Z',updated_at:'2026-11-06T00:00:01Z' }
describe('Windows client closed boundary', () => {
  it('labels the static explanation as saved baseline policy rather than live routing', () => {
    const source = readFileSync(new URL('../src/renderer/src/ClientWorkspace.tsx', import.meta.url), 'utf8')
    expect(source).toContain('解释已保存基础规则')
    expect(source).toContain('已保存基础规则计划')
    expect(source).toContain('办公/家庭覆盖与草稿编辑不代表运行时授权')
    expect(source).not.toContain('解释当前生效规则')
  })
  it('keeps a finite separate method set and accepts daily typed operations', () => {
    expect(CLIENT_METHODS.length).toBe(5)
    expect(validateClientRequest('service.submit',{...envelope,kind:'takeover_start',start:{channels:{company:false,personal:true},mode:'daily'}})).toBe(true)
    expect(validateClientRequest('service.submit',{...envelope,kind:'takeover_start',start:{channels:{company:false,personal:true},mode:'validation',validation_seconds:2700}})).toBe(true)
    expect(()=>validateRequest('workspace.submit',{profile_id:'profile',action:'initialize',request_id:'request',policy_json:'{}'})).not.toThrow()
  })
  it.each([
    {...envelope,kind:'takeover_start',start:{channels:{company:true,personal:false},mode:'validation',validation_seconds:2701}},
    {...envelope,kind:'takeover_start',start:{channels:{company:true,personal:false},mode:'daily',exe:'private-canary'}},
    {...envelope,kind:'exit_restore',stop:{},shell:'private-canary'},
    {...envelope,kind:'exit_restore',stop:{},channels:{company:false,personal:false}},
    {...envelope,kind:'settings_apply',settings:{auto_connect:false,environment:'home',office_overrides:[{type:'domain',value:'example.test',target:'company'}],home_overrides:[]}},
    {...envelope,profile_id:'C:\\private-canary',kind:'exit_restore',stop:{}}
  ])('rejects paths, arbitrary execution, extra payloads and company overrides', value => {
    expect(validateClientRequest('service.submit',value)).toBe(false)
  })
  it('uses exactly one initialization source and source revision preconditions', () => {
    const base={profile_id:'profile',action:'initialize',request_id:'request'}
    expect(validateClientRequest('workspace.submit',{...base,bootstrap_json:'{}'})).toBe(true)
    expect(validateClientRequest('workspace.submit',{...base,policy_json:'{}',bootstrap_json:'{}'})).toBe(false)
    expect(validateClientRequest('workspace.submit',{...base})).toBe(false)
    expect(validateClientRequest('workspace.submit',{profile_id:'profile',action:'sources_save',request_id:'request',sources_json:'{}'})).toBe(false)
    expect(validateClientRequest('workspace.submit',{profile_id:'profile',action:'sources_save',request_id:'request',sources_json:'{}',expected_revision:'revision'})).toBe(true)
    expect(validateClientRequest('workspace.submit',{profile_id:'profile',action:'import_nodes',request_id:'request',content:'x'.repeat(700001)})).toBe(false)
  })
  it('binds auth responses to a positive sequence and exact opaque field set without mixed credentials',()=>{
    const auth={...envelope,kind:'auth_respond',auth:{challenge_id:'challenge',sequence:1,fields:[{field_id:'f0',value:'fixture-secret'}]}}
    expect(validateClientRequest('service.submit',auth)).toBe(true)
    expect(validateClientRequest('service.submit',{...auth,auth:{...auth.auth,sequence:0}})).toBe(false)
    expect(validateClientRequest('service.submit',{...auth,auth:{...auth.auth,password:'mixed'}})).toBe(false)
    expect(validateClientRequest('service.submit',{...auth,auth:{...auth.auth,fields:[...auth.auth.fields,...auth.auth.fields]}})).toBe(false)
    expect(validateClientRequest('service.submit',{...auth,auth:{...auth.auth,fields:[{field_id:'f0',value:'fixture',path:'private-path'}]}})).toBe(false)
  })
  it('requires typed complete operation responses and a bounded safe error', () => {
    expect(validateClientResult('workspace.submit',operation)).toBe(true)
    expect(validateClientResult('service.operation',{...operation,kind:'shell'})).toBe(false)
    expect(validateClientResult('service.operation',{...operation,error:{code:'bad command private-canary',message:'',retryable:false}})).toBe(false)
    expect(validateClientResult('service.operation',{operation_id:'operation',phase:'completed',completed:true,restored:true})).toBe(false)
  })
  it('advertises exactly eight read methods or thirteen explicit Windows client methods',()=>{
    const hello={protocol_major:1,session_id:'session',build:{version:'fixture',os:'windows',arch:'amd64',go_version:'fixture'},mode:'windows_offline',capabilities:{read_only:false,connection_start:true,connection_stop:true,config_write:true,native_lifecycle:false,windows_client:true,methods:[...READ_METHODS,...CLIENT_METHODS]}}
    expect(validateResult('session.hello',hello)).toBe(true)
    expect(validateResult('session.hello',{...hello,build:{...hello.build,os:'darwin'}})).toBe(false)
    expect(validateResult('session.hello',{...hello,capabilities:{...hello.capabilities,methods:[...READ_METHODS]}})).toBe(false)
    expect(validateResult('session.hello',{...hello,capabilities:{...hello.capabilities,read_only:true,connection_start:false,connection_stop:false,config_write:false,windows_client:false}})).toBe(false)
  })
})
