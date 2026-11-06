import type { ServiceSnapshot } from '../../../protocol/client'

export interface ServiceEvidence {
  snapshot: ServiceSnapshot | null
  control: 'connecting'|'available'|'unavailable'
  lastReceivedAt: number | null
}
export const initialServiceEvidence = ():ServiceEvidence => ({snapshot:null,control:'connecting',lastReceivedAt:null})
export function receivedServiceEvidence(previous:ServiceEvidence,snapshot:ServiceSnapshot,now:number):ServiceEvidence {
  if(!Number.isFinite(now))return lostServiceEvidence(previous)
  return {snapshot,control:'available',lastReceivedAt:now}
}
export function lostServiceEvidence(previous:ServiceEvidence):ServiceEvidence {
  return {...previous,snapshot:null,control:'unavailable'}
}
// A successful IPC receipt is not an independent network verification. Once
// reads fail or stop arriving, no prior route/block result remains current.
export function expireServiceEvidence(previous:ServiceEvidence,now:number,maxAge=10000):ServiceEvidence {
  if(!previous.snapshot)return previous
  if(previous.lastReceivedAt===null||!Number.isFinite(now)||now<previous.lastReceivedAt||now-previous.lastReceivedAt>=maxAge)return lostServiceEvidence(previous)
  return previous
}
