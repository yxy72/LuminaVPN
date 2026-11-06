import {describe,it,expect} from 'vitest'
import type {ServiceSnapshot} from '../protocol/client'
import {initialServiceEvidence,receivedServiceEvidence,lostServiceEvidence,expireServiceEvidence} from '../src/renderer/src/service-evidence'

describe('live service evidence presentation',()=>{
  const snapshot={service_state:'available',company:{state:'blocked',route:'vpn',ipv6_state:'blocked'},restored:true} as unknown as ServiceSnapshot
  it('a failed refresh clears all live route/block/restoration claims while retaining only receipt time',()=>{
    const received=receivedServiceEvidence(initialServiceEvidence(),snapshot,100)
    const failed=lostServiceEvidence(received)
    expect(failed.snapshot).toBeNull();expect(failed.control).toBe('unavailable');expect(failed.lastReceivedAt).toBe(100)
    const recovered=receivedServiceEvidence(failed,{...snapshot,company:{desired:false,state:'unknown',route:'unknown'}},300)
    expect(recovered.snapshot?.company.state).toBe('unknown');expect(recovered.lastReceivedAt).toBe(300)
  })
  it('silent/hung reads and a clock rollback expire prior claims without inventing a failure result',()=>{
    const received=receivedServiceEvidence(initialServiceEvidence(),snapshot,100)
    expect(expireServiceEvidence(received,10099).snapshot).toBe(snapshot)
    expect(expireServiceEvidence(received,10100).snapshot).toBeNull()
    expect(expireServiceEvidence(received,99).snapshot).toBeNull()
    expect(initialServiceEvidence().snapshot).toBeNull()
  })
})
