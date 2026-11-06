import {describe,it,expect} from 'vitest'
import {ProfileScope,scopedProfileImport} from '../src/renderer/src/profile-scope'

describe('trusted profile boundaries',()=>{
  it('a delayed old document cannot hydrate the new profile or its different overrides',async()=>{
    const old=new ProfileScope('old-profile'),ticket=old.capture()
    let resolveOld!:(value:{profile_id:string;overrides:string[]})=>void
    let current={profile_id:'new-profile',overrides:['new-direct-rule']}
    const delayed=new Promise<{profile_id:string;overrides:string[]}>(resolve=>{resolveOld=resolve}).then(value=>{if(old.accepts(ticket,value.profile_id))current=value})
    old.close();const next=new ProfileScope('new-profile')
    expect(next.accepts(next.capture(),current.profile_id)).toBe(true)
    resolveOld({profile_id:'old-profile',overrides:['old-personal-rule']});await delayed
    expect(current.overrides).toEqual(['new-direct-rule'])
    old.activate();expect(old.accepts(ticket,'old-profile')).toBe(false)
  })
  it('an old native picker cannot resume into an import for the newly selected profile',async()=>{
    const scope=new ProfileScope('old-profile');let pick!:(value:{import_id:string})=>void
    const writes:{profile_id:string;import_id:string}[]=[]
    const result=scopedProfileImport(scope,()=>new Promise(resolve=>{pick=resolve}),async(profile_id,import_id)=>{writes.push({profile_id,import_id});return{profile_id}})
    scope.close();pick({import_id:'old-grant'})
    expect(await result).toBeNull();expect(writes).toEqual([])
    const next=new ProfileScope('new-profile')
    await scopedProfileImport(next,async()=>({import_id:'new-grant'}),async(profile_id,import_id)=>{writes.push({profile_id,import_id});return{profile_id}})
    expect(writes).toEqual([{profile_id:'new-profile',import_id:'new-grant'}])
  })
})
