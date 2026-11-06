export interface ProfileTicket {profileID:string;generation:number}
export class ProfileScope {
  private generation=0
  private active=true
  constructor(readonly profileID:string){}
  activate():void {this.active=true;this.generation++}
  close():void {this.active=false;this.generation++}
  capture():ProfileTicket {return {profileID:this.profileID,generation:this.generation}}
  accepts(ticket:ProfileTicket,responseProfile:unknown):boolean {return this.active&&ticket.generation===this.generation&&ticket.profileID===this.profileID&&responseProfile===this.profileID}
}
export async function scopedProfileImport<T extends {profile_id:string}>(scope:ProfileScope,pick:(profileID:string)=>Promise<{import_id:string}|null>,submit:(profileID:string,importID:string)=>Promise<T>):Promise<T|null>{
  const ticket=scope.capture(),grant=await pick(scope.profileID)
  if(!grant||!scope.accepts(ticket,scope.profileID))return null
  const result=await submit(scope.profileID,grant.import_id)
  return scope.accepts(ticket,result.profile_id)?result:null
}
