import React, { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { NodeInventory } from './NodeInventory'
import { RuleListField, lines } from './RuleListField'
import { WorkspaceStatus } from './WorkspaceStatus'
import type { ClientAPI, DesiredChannels, MacStartEnvironment, ServiceMutation, ServiceOperation, ServiceSnapshot, WorkspaceReadBody, WorkspaceWrite, WorkspaceCommand, EnvironmentOverride } from '../../../protocol/client'
import { canPreemptMacRuntimeOperation, validateWorkspaceActivity } from '../../../protocol/client'
import type { Nodes, Subscriptions, Environment, Config } from '../../../protocol/types'
import { isRecord } from '../../../protocol/validation-base'
import {ProfileScope,scopedProfileImport} from './profile-scope'
import { MacLifecycle, macOperationText } from './MacLifecycle'
import { ConnectionChannels } from './ChannelProbeStatus'
import { MacRecovery, matchesMacDiagnosticRecovery, submitMacDiagnosticRecovery, type MacRecoveryRequest } from './MacRecovery'
import {initialServiceEvidence,receivedServiceEvidence,lostServiceEvidence,expireServiceEvidence} from './service-evidence'

type Page = 'overview' | 'nodes' | 'rules' | 'diagnostics' | 'settings'
type PolicyDocument = Record<string, unknown>
const initialPolicy = (): PolicyDocument => ({ version: 1, company: { domains: [], cidrs: [], dns: [] }, personal: { domains: [], cidrs: [], dns: [] }, direct_dns: [], vpn: { server: '', endpoint_ipv4: '' }, ports: { proxy: 7890, dns: 1053 }, probes: [], personal_rules: [] })
const pretty = (x: unknown) => JSON.stringify(x, null, 2)
function safeError(error: unknown): string { const code = isRecord(error) && typeof error.code === 'string' && /^[A-Z_]{1,64}$/.test(error.code) ? error.code : 'CLIENT_OPERATION_FAILED'; return ({ SERVICE_UNAVAILABLE: '后台服务不可用。请检查安装状态；现有连接是否已恢复尚未确认。', PROFILE_NOT_ENROLLED:'此配置尚未登记到后台服务。配置标识不能代替系统登记，连接状态未确认。', PROFILE_UNAVAILABLE:'后台尚无此配置的可信登记。连接状态未确认。', REVISION_CONFLICT: '配置已被其他操作更新，请重新读取并检查差异。', AUTH_REQUIRED: '请完成新的认证挑战。', CLIENT_UNAVAILABLE: '当前平台未提供此操作。', PROFILE_BUSY: '已有配置操作或配置切换正在进行。', EXIT_WORKSPACE_BUSY: '当前操作还在进行，请等待完成后退出。', EXIT_WORKSPACE_STATUS_UNAVAILABLE: '无法确认配置操作已完成。请刷新工作空间后重试。', OPERATION_NOT_FOUND: '操作记录已失效，请重新读取已保存配置。', MAC_START_FAILED: '连接未完成。请检查所选通道的配置及 macOS 授权。', MAC_AUTH_REQUIRED: '公司 VPN 需要有效会话，请在终端完成公司认证后再连接。', MAC_AUTH_FAILED: '公司认证未完成。请检查公司配置或终端提示。', MAC_OPERATION_INTERRUPTED: '网络操作已中断，请检查运行并按需使用恢复入口。', MAC_RECOVERY_UNCONFIRMED: '管理员恢复未确认。请检查诊断页后重试。', MAC_STOP_UNCONFIRMED: '停止报告尚未收到，请检查诊断页。', MAC_PERSONAL_UNAVAILABLE: '当前运行不支持切换个人代理，可在下次连接时调整。', MAC_PERSONAL_UNCONFIRMED: '个人代理设置尚未确认，请刷新当前运行状态。', RECOVERY_REQUIRED: '上一运行需要先确认恢复。', RUN_UNCONFIRMED: '无法绑定当前运行，请刷新诊断页。', EXIT_RESTORE_UNAVAILABLE: '当前运行的管理员恢复未确认，窗口保持打开。', EXIT_RESTORE_FAILED: '恢复操作未完成，窗口保持打开。', EXIT_RESTORE_UNCONFIRMED: '管理员恢复未确认，窗口保持打开。', EXIT_OPERATION_MISMATCH: '当前运行与恢复操作不匹配，请刷新诊断。', EXIT_RESTORE_TIMEOUT: '等待管理员恢复超时，窗口保持打开。' } as Record<string,string>)[code] ?? '操作未完成。请保留恢复入口，刷新状态后检查。' }
function OverrideEditor({title,value,onChange}:{title:string;value:string;onChange:(value:string)=>void}) {
  const [type,setType]=useState<EnvironmentOverride['type']>('domain'),[target,setTarget]=useState<EnvironmentOverride['target']>('personal'),[rule,setRule]=useState(''),[editing,setEditing]=useState<number|null>(null)
  let rows:EnvironmentOverride[]=[];try{const parsed:unknown=JSON.parse(value);if(Array.isArray(parsed)&&parsed.every(isRecord))rows=parsed as unknown as EnvironmentOverride[]}catch{}
  return <section className="client-card"><h2>{title}覆盖</h2><p>初始为空，仅允许个人代理或直连。公司精确授权始终优先。</p><div className="client-actions"><select aria-label={`${title}规则类型`} value={type} onChange={e=>setType(e.target.value as EnvironmentOverride['type'])}><option value="domain">精确域名</option><option value="domain_suffix">域名后缀</option><option value="cidr">网段</option></select><input aria-label={`${title}规则值`} value={rule} onChange={e=>setRule(e.target.value)}/><select aria-label={`${title}规则出口`} value={target} onChange={e=>setTarget(e.target.value as EnvironmentOverride['target'])}><option value="personal">个人代理</option><option value="direct">直连</option></select><button disabled={!rule.trim()} onClick={()=>{const next={type,value:rule.trim(),target};onChange(pretty(editing===null?[...rows,next]:rows.map((r,i)=>i===editing?next:r)));setRule('');setEditing(null)}}>{editing===null?'添加':'更新'}</button></div><ul>{rows.map((r,i)=><li key={i}>{r.type} · {r.value} → {r.target} <button onClick={()=>{setType(r.type);setTarget(r.target);setRule(r.value);setEditing(i)}}>编辑</button><button onClick={()=>{onChange(pretty(rows.filter((_,at)=>at!==i)));setEditing(null)}}>删除</button></li>)}</ul></section>
}
function SourceEditor({value,onChange}:{value:string;onChange:(value:string)=>void}) {
  const [url,setURL]=useState(''),[format,setFormat]=useState('classical'),[target,setTarget]=useState('personal'),[editing,setEditing]=useState<number|null>(null)
  let doc:Record<string,unknown>={};try{const x:unknown=JSON.parse(value);if(isRecord(x))doc=x}catch{}
  const node=isRecord(doc.nodes)?doc.nodes:{},rules=Array.isArray(doc.rules)?doc.rules.filter(isRecord):[]
  const change=(patch:Record<string,unknown>)=>onChange(pretty({...doc,...patch}))
  return <div className="client-source-editor"><label>节点订阅 HTTPS 链接<input type="url" autoComplete="off" maxLength={8192} value={typeof node.url==='string'?node.url:''} onChange={e=>change({nodes:{...node,url:e.target.value}})}/></label><label>更新间隔（分钟）<input type="number" min={1} max={10080} value={typeof doc.interval_minutes==='number'?doc.interval_minutes:60} onChange={e=>change({interval_minutes:Number(e.target.value)})}/></label><h3>规则来源</h3><div className="client-actions"><input aria-label="规则订阅 HTTPS 链接" type="url" autoComplete="off" value={url} onChange={e=>setURL(e.target.value)}/><select aria-label="规则格式" value={format} onChange={e=>setFormat(e.target.value)}><option value="classical">Classical</option><option value="domain">域名</option><option value="ipcidr">IP 网段</option></select><select aria-label="订阅规则出口" value={target} onChange={e=>setTarget(e.target.value)}><option value="personal">个人代理</option><option value="direct">直连</option></select><button disabled={!url.trim()||editing===null&&rules.length>=8} onClick={()=>{const next={url:url.trim(),format,target};change({rules:editing===null?[...rules,next]:rules.map((r,i)=>i===editing?next:r)});setURL('');setEditing(null)}}>{editing===null?'添加来源':'更新来源'}</button></div><ul>{rules.map((r,i)=><li key={i}>来源 {i+1} · {String(r.format??'classical')} → {String(r.target??'personal')} <button onClick={()=>{setURL(String(r.url??''));setFormat(String(r.format??'classical'));setTarget(String(r.target??'personal'));setEditing(i)}}>编辑</button><button onClick={()=>{change({rules:rules.filter((_,at)=>at!==i)});setEditing(null)}}>删除</button></li>)}</ul><p>现有私密链接不会从后台回显。表单只编辑本次输入；保存来源不会立即更改现有连接。</p></div>
}
function ProbeEditor({rows,onChange}:{rows:Record<string,unknown>[];onChange:(rows:Record<string,unknown>[])=>void}) {
  const [url,setURL]=useState(''),[channel,setChannel]=useState('direct'),[purpose,setPurpose]=useState('path'),[statuses,setStatuses]=useState(''),[editing,setEditing]=useState<number|null>(null)
  return <section className="client-card"><h2>连接检查目标</h2><p>路径可达与服务响应分开判断。每个开启的通道需有对应检查目标。</p><label>HTTPS 检查地址<input type="url" value={url} onChange={e=>setURL(e.target.value)}/></label><div className="client-actions"><select aria-label="检查通道" value={channel} onChange={e=>setChannel(e.target.value)}><option value="direct">直连</option><option value="company">公司</option><option value="personal">个人</option></select><select aria-label="检查用途" value={purpose} onChange={e=>setPurpose(e.target.value)}><option value="path">路径可达</option><option value="service">服务状态</option></select>{purpose==='service'&&<input aria-label="接受的 HTTP 状态码" placeholder="状态码（逗号分隔，可留空）" value={statuses} onChange={e=>setStatuses(e.target.value)}/>}<button disabled={!url.trim()} onClick={()=>{const codes=lines(statuses).map(Number);const next={url:url.trim(),channel,purpose,...(purpose==='service'&&codes.length?{expected_status:codes}:{})};onChange(editing===null?[...rows,next]:rows.map((r,i)=>i===editing?next:r));setURL('');setStatuses('');setEditing(null)}}>{editing===null?'添加检查':'更新检查'}</button></div><ul>{rows.map((r,i)=><li key={i}>{String(r.channel)} · {String(r.purpose??'默认用途')} · {String(r.url)} <button onClick={()=>{setURL(String(r.url));setChannel(String(r.channel));setPurpose(String(r.purpose??(r.channel==='personal'?'service':'path')));setStatuses(Array.isArray(r.expected_status)?r.expected_status.join(','):'');setEditing(i)}}>编辑</button><button onClick={()=>{onChange(rows.filter((_,at)=>at!==i));setEditing(null)}}>删除</button></li>)}</ul></section>
}
export function ClientWorkspace({ page, statusTarget, api, refreshInventory, nodes, savedNode, subscriptions, config, loadNodes, loadRules, chooseProfile, restoreDefaultProfile, checking, environmentCheck, checkEnvironment, showRecovery,validationOnly,profileID,windowsClient,macosClient,configured }: { profileID:string;validationOnly:boolean;windowsClient:boolean;macosClient:boolean;configured:boolean;page: Page; statusTarget: HTMLDivElement|null; api: ClientAPI; refreshInventory: () => void; nodes:Nodes|null; savedNode?: string | null; subscriptions:Subscriptions|null;config:Config|null;loadNodes:(offset:number)=>void;loadRules:(offset:number)=>void;chooseProfile:()=>Promise<void>;restoreDefaultProfile:()=>Promise<void>;checking:boolean;environmentCheck:Environment|null;checkEnvironment:()=>void;showRecovery:()=>void }) {
  const scope=useRef(new ProfileScope(profileID)).current
  const stale=()=>Object.assign(new Error('PROFILE_CHANGED'),{code:'PROFILE_CHANGED'})
  const scopedRead=async(request:WorkspaceReadBody)=>{const ticket=scope.capture();const value=await api.read({...request,profile_id:profileID});if(!scope.accepts(ticket,value.profile_id))throw stale();return value}
  const scopedSnapshot=async()=>{const ticket=scope.capture();const value=await api.snapshot();if(!scope.accepts(ticket,value.profile_id))throw stale();return value}
  const scopedOperation=async(id:string)=>{const ticket=scope.capture();const value=await api.operation(id);if(!scope.accepts(ticket,value.profile_id))throw stale();return value}
  const scopedCommand=async(request:WorkspaceWrite)=>{const ticket=scope.capture();const value=await api.command({...request,profile_id:profileID});if(!scope.accepts(ticket,value.profile_id))throw stale();return value}
  const scopedSubmit=async(request:ServiceMutation)=>{const ticket=scope.capture();const value=await api.submit(request);if(!scope.accepts(ticket,value.profile_id))throw stale();return value}
  const connectionControl = windowsClient || macosClient
  const [evidence,setEvidence]=useState(initialServiceEvidence)
  const snapshot=evidence.snapshot
  const [desired, setDesired] = useState<DesiredChannels>({ company: false, personal: false })
  const [macEnvironment, setMacEnvironment] = useState<MacStartEnvironment>('shared')
  const [validationSeconds,setValidationSeconds]=useState('')
  const [policyText, setPolicyText] = useState(pretty(initialPolicy()))
  const [revision, setRevision] = useState('')
  const [savedPolicyText, setSavedPolicyText] = useState<string | null>(null)
  const [policyFeedback, setPolicyFeedback] = useState<{ message: string; error?: boolean } | null>(null)
  const [savingPolicy, setSavingPolicy] = useState(false)
  const pendingPolicy = useRef<{ requestID: string; draft: string } | null>(null)
  const [sources, setSources] = useState('')
  const [sourcesPresent,setSourcesPresent]=useState(false),[sourceReplacement,setSourceReplacement]=useState(false)
  const [bootstrap,setBootstrap]=useState(''),[initializeMode,setInitializeMode]=useState<'policy'|'bootstrap'>('policy')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [result, setResult] = useState<{ page: Page; value: Record<string, unknown> } | null>(null)
  const [operation, setOperation] = useState<ServiceOperation | null>(null)
  const [username, setUsername] = useState('')
  const [authFields,setAuthFields]=useState<Record<string,string>>({})
  const [password, setPassword] = useState(''), [otp, setOTP] = useState('')
  const [target, setTarget] = useState(''), [rollback, setRollback] = useState(''), [cleanupID, setCleanupID] = useState('')
  const [ruleType, setRuleType] = useState('DOMAIN'), [ruleTarget, setRuleTarget] = useState('personal'), [ruleValue, setRuleValue] = useState('')
  const [editingRule,setEditingRule]=useState<number|null>(null)
  const [environment, setEnvironment] = useState<'office'|'home'>('home')
  const [officeRules, setOfficeRules] = useState('[]'), [homeRules, setHomeRules] = useState('[]')
  const mounted = useRef(true), reading = useRef(false), editedChannels = useRef(false), loadedDocument = useRef(false), loadedSettings=useRef(false)
  const pending = useRef<string | null>(null), lastOperation = useRef<string | null>(null)
  const submitting = useRef(false)
  const diagnosticRecovery = useRef<{ id: string; request: MacRecoveryRequest } | null>(null)
  const latest = useRef<ServiceSnapshot | null>(null)
  const [workspaceActivity, setWorkspaceActivity] = useState<boolean | null>(null)
  const canControl = windowsClient ? snapshot?.service_state === 'available' : workspaceActivity === false
  const macPreemptible = macosClient && snapshot !== null && canPreemptMacRuntimeOperation(snapshot, operation)
  const receiveDocument = (doc: Record<string, unknown>, submittedDraft?: string) => {
    const text = typeof doc.policy_json === 'string' ? doc.policy_json
      : isRecord(doc.policy) ? pretty(doc.policy) : null
    if (text !== null) {
      setSavedPolicyText(text)
      setPolicyText(current => submittedDraft === undefined || current === submittedDraft ? text : current)
    }
    setRevision(typeof doc.revision === 'string' ? doc.revision : '')
    if (typeof doc.sources_json === 'string') setSources(doc.sources_json)
    if (isRecord(doc.sources)) setSourcesPresent(doc.sources.present === true)
  }
  const finishPolicy = async (next: ServiceOperation) => {
    const change = pendingPolicy.current
    if (!change || change.requestID !== next.request_id) return
    try {
      if (next.error) throw next.error
      const doc = await scopedRead({ action: 'document' })
      if (!mounted.current) return
      if (typeof doc.revision !== 'string' || !(typeof doc.policy_json === 'string' || isRecord(doc.policy))) throw new Error('INVALID_PROTOCOL')
      receiveDocument(doc, change.draft)
      setPolicyFeedback({ message: '配置操作已完成。下次连接使用已保存的规则。' })
    } catch (error) {
      if (mounted.current) setPolicyFeedback({
        message: next.error ? `保存未完成。草稿已保留。 ${safeError(error)}` : '操作已完成。请重新读取配置以确认保存结果。',
        error: true,
      })
    } finally {
      pendingPolicy.current = null
      if (mounted.current) setSavingPolicy(false)
    }
  }
  const refreshDocumentMetadata = async () => {
    // Never advance a draft's revision without replacing its document. This
    // preserves compare-and-swap protection if another host edited the policy.
    try { const doc=await scopedRead({action:'document'});if(!mounted.current)return;if(isRecord(doc.sources))setSourcesPresent(doc.sources.present===true) } catch {}
  }
  const refresh = async () => {
    if (reading.current) return
    reading.current = true
    try {
      let localActive = false
      if (!windowsClient) {
        const activity = await scopedRead({ action: 'activity' })
        if (!validateWorkspaceActivity(activity)) throw new Error('INVALID_PROTOCOL')
        if (!mounted.current) return
        localActive = activity.active
        setWorkspaceActivity(activity.active)
      }
      if (connectionControl) {
        const current = await scopedSnapshot()
        if (!mounted.current) return
        latest.current = current.service_state === (windowsClient ? 'available' : 'local') ? current : null
        setEvidence(previous => receivedServiceEvidence(previous, current, Date.now()))
        if (windowsClient && !loadedSettings.current && current.settings) {
          loadedSettings.current = true
          setEnvironment(current.settings.environment)
          setOfficeRules(pretty(current.settings.office_overrides))
          setHomeRules(pretty(current.settings.home_overrides))
        }
        if (!submitting.current && current.operation_id && current.operation_id !== lastOperation.current) {
          pending.current = current.operation_id
          lastOperation.current = current.operation_id
        }
        if (windowsClient && !editedChannels.current) setDesired(current.desired)
      }

      const id = pending.current
      if (id && !submitting.current) {
        let next: ServiceOperation
        try { next = await scopedOperation(id) }
        catch (error) {
          // A restarted local bridge cannot report a previous process's operation.
          // An authoritative idle check permits editing again without inferring success.
          if (!windowsClient && mounted.current && pending.current === id && !localActive &&
              isRecord(error) && error.code === 'OPERATION_NOT_FOUND') {
            if (diagnosticRecovery.current?.id === id) diagnosticRecovery.current = null
            pending.current = null
            setOperation(null)
            if (pendingPolicy.current) {
              pendingPolicy.current = null
              setSavingPolicy(false)
              setPolicyFeedback({ message: '保存结果待确认。请重新读取已保存配置。', error: true })
            }
            setBusy(false)
            setError(safeError(error))
            return
          }
          throw error
        }
        if (!mounted.current || submitting.current || pending.current !== id) return
        if (next.operation_id !== id) throw new Error('OPERATION_MISMATCH')
        const recovery = diagnosticRecovery.current
        if (recovery?.id === id && !matchesMacDiagnosticRecovery(next, recovery.request)) {
          throw Object.assign(new Error('MAC_RECOVERY_UNCONFIRMED'), { code: 'MAC_RECOVERY_UNCONFIRMED' })
        }
        setOperation(next)
        if (next.completed || next.error) {
          if (recovery?.id === id) diagnosticRecovery.current = null
          pending.current = null
          setBusy(false)
          refreshInventory()
          if (next.kind === 'workspace') void finishPolicy(next)
          if (next.error) setError(safeError(next.error))
          else {
            setNotice(operationNotice(next))
            if (next.kind === 'workspace') void refreshDocumentMetadata()
          }
        }
      }
    } catch (error) {
      if (mounted.current) {
        latest.current = null
        setEvidence(lostServiceEvidence)
        setWorkspaceActivity(null)
        setError(safeError(error))
      }
    }
    finally { reading.current = false }
  }
  useEffect(() => {
    mounted.current = true;scope.activate()
    void refresh()
    if (!loadedDocument.current) {
      loadedDocument.current = true
      void scopedRead({ action: 'document' }).then(doc => {
        if (!mounted.current) return
        receiveDocument(doc)
      }).catch(() => {})
    }
    const timer = window.setInterval(() => {
      if (connectionControl) setEvidence(previous => {
        const next = expireServiceEvidence(previous, Date.now())
        if (!next.snapshot) latest.current = null
        return next
      })
      void refresh()
    }, 1500)
    const remove = api.onExitError(code => setError(windowsClient
      ? '停止或恢复尚未完成，界面保持打开。请检查后台操作并使用恢复入口。'
      : safeError({ code })))
    return () => { mounted.current = false;scope.close(); window.clearInterval(timer); remove(); setPassword(''); setOTP('') }
  }, [api, windowsClient, macosClient])
  useEffect(()=>{setPassword('');setOTP('');setAuthFields({})},[snapshot?.challenge?.challenge_id,snapshot?.challenge?.sequence])
  const read = async (request: WorkspaceReadBody) => {
    setError(null)
    try {
      const value = await scopedRead(request)
      if (request.action === 'document') {
        receiveDocument(value)
        setPolicyFeedback(null)
      } else setResult({ page, value })
    } catch (error) { setError(safeError(error)) }
  }
  const operationNotice = (next: ServiceOperation): string => {
    if (next.kind === 'workspace' || next.kind === 'settings_apply') return '配置操作已完成，请重新读取保存结果。'
    if (macosClient && next.phase === 'authenticated') return next.run_ref ? '本次运行的公司会话已更新。' : '公司认证已完成，可以连接网络。'
    if (macosClient && next.phase === 'company_applied') return '公司 VPN 设置已应用到本次运行。'
    if (macosClient && next.phase === 'personal_applied') return '个人代理设置已应用到本次运行。'
    if (macosClient && next.phase === 'managed_reported') return '网络接管已启动，通道验证结果在总览更新。'
    if (macosClient && next.phase === 'ready_reported') return '已收到运行报告，可在总览查看检查结果。'
    if (macosClient && next.phase === 'stopped_reported') return '已收到停止报告。管理员恢复仍待确认。'
    if (macosClient && next.kind === 'exit_restore' && next.phase === 'restored' && next.restored) return '管理员已确认本次运行的恢复。'
    return '操作完成。'
  }
  const accepted = (next: ServiceOperation) => {
    lastOperation.current = next.operation_id
    setOperation(next)
    pending.current = next.completed ? null : next.operation_id
    setBusy(!next.completed)
    if (next.error) setError(safeError(next.error))
    else setNotice(next.completed ? operationNotice(next)
      : next.kind === 'workspace' ? '配置操作进行中，请保持应用打开。'
        : windowsClient ? '后台服务已接受操作。'
          : next.kind === 'auth_begin' ? '请在本机 Terminal 完成公司认证。'
            : next.kind === 'channels_set' ? '正在应用本次运行的通道设置。' : '网络操作进行中，请留意 macOS 授权提示。')
    if (next.completed && next.kind === 'workspace') {
      void finishPolicy(next)
      if (!next.error) void refreshDocumentMetadata()
    }
    editedChannels.current = false
    void refresh()
  }
  const command = async (request: WorkspaceCommand) => {
    if (!canControl) {
      setError(windowsClient ? '后台服务尚未确认可用。' : '请等待当前配置操作完成，或刷新工作空间。')
      return
    }
    const requestID = crypto.randomUUID()
    const policyChange = request.action === 'apply' || request.action === 'initialize' || request.action === 'rollback'
    if (policyChange) {
      if (pendingPolicy.current) return
      pendingPolicy.current = { requestID, draft: policyText }
      setSavingPolicy(true)
      setPolicyFeedback(null)
    }
    setBusy(true); setError(null); setNotice(null)
    try {
      accepted(await scopedCommand({ ...request, profile_id: profileID, request_id: requestID } as WorkspaceWrite) as ServiceOperation)
    } catch (error) {
      setBusy(false)
      setError(safeError(error))
      if (policyChange) {
        pendingPolicy.current = null
        setSavingPolicy(false)
        setPolicyFeedback({ message: `保存未完成。草稿已保留。 ${safeError(error)}`, error: true })
      }
    }
  }
  const submit = async (request: Record<string, unknown>, bindRun = true) => {
    let current = connectionControl ? latest.current : null
    if (!current) { setError('后台状态未确认，未发出变更。'); return }
    if (submitting.current) return
    submitting.current = true
    setBusy(true); setError(null); setNotice(null)
    try {
      if (macosClient && request.kind === 'exit_restore') {
        const { operation, request: recovery } = await submitMacDiagnosticRecovery(snapshot, crypto.randomUUID(), {
          snapshot: scopedSnapshot,
          submit: scopedSubmit,
        })
        diagnosticRecovery.current = operation.completed ? null : { id: operation.operation_id, request: recovery }
        accepted(operation)
        return
      }
      if (macosClient && request.kind === 'takeover_stop') {
        if (current.run_ref !== snapshot?.run_ref) throw stale()
        if (macPreemptible) {
          const verified = await scopedSnapshot()
          if (verified.run_ref !== current.run_ref || verified.service_state !== 'local') throw stale()
          current = verified
        }
      }
      const runRef = bindRun ? current.run_ref : undefined
      accepted(await scopedSubmit({
        request_id: crypto.randomUUID(), profile_id: current.profile_id, expected_revision: current.revision,
        ...(runRef ? { run_ref: runRef } : {}), ...request,
      } as ServiceMutation))
    } catch (e) {
      setBusy(false); setError(safeError(e))
    } finally { submitting.current = false }
  }
  const runtimeChannel = (channel: keyof DesiredChannels) => {
    const current = latest.current
    const available = channel === 'company' ? current?.mac_company_control : current?.mac_personal_control
    if (available === true && current?.run_ref && current.run_ref === snapshot?.run_ref) return current
    setError('当前运行待确认，请刷新后重试。')
    return null
  }
  const edit = (section: string, key: string, value: unknown) => {
    try { const doc = JSON.parse(policyText) as PolicyDocument; const parent = isRecord(doc[section]) ? doc[section] as Record<string, unknown> : {}; doc[section] = { ...parent, [key]: value }; updatePolicyText(pretty(doc)) } catch { setError('策略 JSON 格式需要先修正。') }
  }
  let document: PolicyDocument = {}
  let validDraft = false
  try {
    const value: unknown = JSON.parse(policyText)
    if (isRecord(value)) { document = value; validDraft = true }
  } catch {}
  const dirtyPolicy = savedPolicyText !== null && policyText !== savedPolicyText
  const updatePolicyText = (next: string) => { setPolicyText(next); setPolicyFeedback(null) }
  const savePolicy = () => { void command({ action: 'apply', policy_json: policyText, expected_revision: revision }) }
  const saveDisabled = busy || savingPolicy || !canControl || !revision || !dirtyPolicy || !validDraft
  const group = (name: string): Record<string,unknown> => isRecord(document[name]) ? document[name] as Record<string,unknown> : {}
  const rules = Array.isArray(document.personal_rules) ? document.personal_rules.filter(isRecord) : []
  const importNodes = async () => {if(!canControl){setError(windowsClient ? '后台服务尚未确认可用。' : '请等待当前配置操作完成，或刷新工作空间。');return};try{const next=await scopedProfileImport(scope,id=>api.pickImport(id),(id,grant)=>api.importNodes(crypto.randomUUID(),grant,id));if(next){setBusy(true);accepted(next)}}catch(e){setBusy(false);setError(safeError(e))}}

  const authSubmit = async (event: React.FormEvent) => { event.preventDefault(); const challenge = latest.current?.challenge; if (!challenge || !Number.isFinite(Date.parse(challenge.expires_at)) || Date.parse(challenge.expires_at)<=Date.now()) {setPassword('');setOTP('');setError('认证挑战已到期，请刷新并等待新的挑战。');return}; const credentials = { kind:'auth_respond', auth:{ challenge_id:challenge.challenge_id, sequence:challenge.sequence, ...(challenge.fields?.length?{fields:challenge.fields.map(field=>({field_id:field.field_id,value:authFields[field.field_id]??''}))}:{...(challenge.kind==='username'&&username?{username}:{}),...(challenge.kind==='password'&&password?{password}:{}),...(challenge.kind==='otp'&&otp?{otp}:{})}) } }; setPassword('');setOTP('');setAuthFields({}); await submit(credentials) }
  const applySettings = () => { try { const office:unknown=JSON.parse(officeRules),home:unknown=JSON.parse(homeRules); if(!Array.isArray(office)||!Array.isArray(home)) throw new Error(); const allowed=(rows:unknown[])=>rows.every(r=>isRecord(r)&&['personal','direct'].includes(String(r.target))&&typeof r.value==='string'); if(!allowed(office)||!allowed(home)) throw new Error(); void submit({kind:'settings_apply',settings:{auto_connect:false,environment,office_overrides:office,home_overrides:home}}) } catch {setError('环境覆盖必须是规则数组，target 只能是 personal 或 direct。')} }
  const operationText = operation && (windowsClient
    ? `后台操作记录 ${operation.kind} · ${operation.phase}${operation.restored ? ' · 已确认恢复' : ''}`
    : macOperationText(operation))
  const inProgress = busy || workspaceActivity === true || operation?.completed === false
  const statusLabel = error ? '操作需检查' : inProgress
    ? operation?.kind === 'workspace' || savingPolicy ? '配置操作进行中' : '操作进行中'
    : windowsClient ? snapshot?.service_state === 'available' ? '后台服务可用' : '后台服务待确认'
      : workspaceActivity === null ? '正在确认配置' : '配置可编辑'
  return <section className="client-workspace">
    {statusTarget && createPortal(<WorkspaceStatus key={page} label={statusLabel} running={inProgress} problem={!!error}>
      <strong>{windowsClient ? '后台服务' : '本机配置'}</strong>
      {windowsClient && <p>{evidence.control === 'available' ? '状态读取可用' : '后台状态待确认'}
        {evidence.lastReceivedAt !== null && ` · ${new Date(evidence.lastReceivedAt).toLocaleTimeString()}`}</p>}
      {!windowsClient && workspaceActivity === null && <p>正在核对配置操作。</p>}
      {operationText && <p>{operationText}</p>}
      {notice && <p>{notice}</p>}
      {error && <p>{error}</p>}
      <button className="link-btn" onClick={() => { setError(null); void refresh() }}>刷新工作空间</button>
    </WorkspaceStatus>, statusTarget)}
    {error && <div className="control-banner" role="alert">{error}<button className="link-btn" onClick={() => { setError(null); void refresh() }}>刷新工作空间</button></div>}
    {page === 'overview' && !connectionControl && <section className="client-card">
      <h2>本机配置</h2><p>{configured ? '配置可在工作空间设置中查看。' : '请在工作空间设置中初始化配置。'}</p>
    </section>}
    {page === 'overview' && macosClient && <MacLifecycle snapshot={snapshot} configured={configured}
      busy={busy || workspaceActivity !== false} preemptible={macPreemptible} desired={desired} setDesired={setDesired}
      environment={macEnvironment} setEnvironment={setMacEnvironment}
      start={start => { void submit({ kind: 'takeover_start', start }) }}
      setChannel={(channel, enabled) => {
        const current = runtimeChannel(channel)
        if (current && current.desired[channel] !== enabled) {
          void submit({ kind: 'channels_set', channels: { ...current.desired, [channel]: enabled } })
        }
      }}
      authenticate={runtime => {
        if (!runtime || runtimeChannel('company')?.desired.company) void submit({ kind: 'auth_begin', begin_auth: {} }, runtime)
      }}
      stop={() => { void submit({ kind: 'takeover_stop', stop: {} }) }} exit={() => { void api.exit() }} />}
    {page === 'overview' && windowsClient && <section className="client-card connection-overview">
      <h2>网络接管</h2>
      <p role="status">{snapshot?.takeover_state === 'idle' ? '当前未连接' : snapshot?.takeover_state === 'ready' ? '接管已就绪' : snapshot ? '连接状态以三路出口为准' : '正在确认后台状态'}</p>
      <ConnectionChannels snapshot={snapshot} />
      <div className="client-actions">
        {(['company', 'personal'] as const).map(channel => <label key={channel}>
          <input type="checkbox" checked={desired[channel]} onChange={event => {
            editedChannels.current = true
            setDesired({ ...desired, [channel]: event.target.checked })
          }} />开启{channel === 'company' ? '公司 VPN' : '个人代理'}
        </label>)}
      </div>
      {validationOnly&&<label>本次验证时长（秒，1–2700；到期自动停止与恢复）<input type="number" min={1} max={2700} required value={validationSeconds} onChange={e=>setValidationSeconds(e.target.value)}/></label>}<div className="client-actions"><button className="client-primary" disabled={busy||!canControl||snapshot?.recovery_required||validationOnly&&(!Number.isInteger(Number(validationSeconds))||Number(validationSeconds)<1||Number(validationSeconds)>2700)} onClick={() => {void submit({kind:'takeover_start',start:validationOnly?{channels:desired,mode:'validation',validation_seconds:Number(validationSeconds)}:{channels:desired,mode:'daily'}})}}>启动网络接管</button><button disabled={busy||!canControl} onClick={() => {void submit({kind:'channels_set',channels:desired})}}>应用通道开关</button><button disabled={!canControl||busy&&(operation?.kind==='takeover_stop'||operation?.kind==='exit_restore')} onClick={() => {void submit({kind:'takeover_stop',stop:{}})}}>停止并恢复</button><button onClick={() => {void api.exit()}}>停止、恢复并退出</button></div>
      {snapshot?.challenge && <form className="client-card" onSubmit={authSubmit} autoComplete="off"><h2>公司认证</h2><p>挑战到期：{snapshot.challenge.expires_at}。密码与动态码只用于本次挑战，不会保存。</p>{snapshot.challenge.fields?.length?snapshot.challenge.fields.map(field=><label key={field.field_id}>{({ACCOUNT:'账户',SECRET:'密码 / 认证信息',SECOND_SECRET:'第二项认证信息',PASSCODE:'口令',OTP:'动态码',AUTH_GROUP:'认证组'} as Record<string,string>)[field.label_code??'']??'认证字段'} · {field.field_id}{field.kind==='select'?<select required value={authFields[field.field_id]??''} onChange={e=>setAuthFields({...authFields,[field.field_id]:e.target.value})}><option value="">请选择</option>{field.choices?.map(choice=><option key={choice.choice_id} value={choice.choice_id}>{choice.label}</option>)}</select>:<input required type={field.kind==='password'||field.kind==='otp'?'password':'text'} autoComplete="off" maxLength={4096} value={authFields[field.field_id]??''} onChange={e=>setAuthFields({...authFields,[field.field_id]:e.target.value})}/>}</label>):<>{snapshot.challenge.kind==='username'&&<label>账户<input required autoComplete="off" maxLength={256} value={username} onChange={e=>setUsername(e.target.value)}/></label>}{snapshot.challenge.kind==='password'&&<label>密码<input required type="password" autoComplete="new-password" maxLength={4096} value={password} onChange={e=>setPassword(e.target.value)}/></label>}{snapshot.challenge.kind==='otp'&&<label>动态码<input required inputMode="numeric" type="password" autoComplete="off" maxLength={1024} value={otp} onChange={e=>setOTP(e.target.value)}/></label>}</>}<button type="submit">提交本次认证</button><button type="button" onClick={()=>{setPassword('');setOTP('');void submit({kind:'auth_cancel',cancel_auth:{challenge_id:snapshot.challenge!.challenge_id}})}}>取消认证</button></form>}
    </section>}
    {(page === 'rules' || page === 'settings') && <>
      <h1>{page === 'rules' ? '白名单与覆盖规则' : '本地配置与历史'}</h1>
      <div className="policy-toolbar">
        <div>
          <strong>{savingPolicy ? '正在保存' : !revision ? '等待配置信息' : dirtyPolicy ? '有未保存的修改' : '配置已保存'}</strong>
          {policyFeedback ? <p role={policyFeedback.error ? 'alert' : 'status'}>{policyFeedback.message}</p>
            : <p>{!revision ? '已有配置加载后可保存。新配置可在工作空间设置中初始化。' : '编辑只更新草稿。保存后的配置从下次连接起生效。'}</p>}
        </div>
        <button className="client-primary" disabled={saveDisabled} onClick={savePolicy}>保存配置</button>
      </div>
    </>}
    {page === 'rules' && <>
      <div className="client-grid">
        {(['company', 'personal'] as const).map(name => <section className="client-card whitelist-card" key={name}>
          <h2>{name === 'company' ? '公司 VPN 白名单' : '个人代理白名单'}</h2>
          <p>{name === 'company' ? '接管期间优先走公司 VPN。公司通道关闭时阻断。' : '个人通道开启时走代理，关闭后走直连。'}</p>
          <fieldset disabled={savedPolicyText === null || !validDraft || savingPolicy}>
            <RuleListField label={name === 'company' ? '公司精确域名' : '个人精确域名'} value={group(name).domains}
              hint="每行一个完整域名，不带协议、端口或通配符。"
              example={name === 'company' ? 'git.corp.example.com' : 'www.example.org'} onChange={value => edit(name, 'domains', value)} />
            <RuleListField label={name === 'company' ? '公司 IPv4 网段' : '个人 IPv4 网段'} value={group(name).cidrs}
              hint="每行一个 /24–/32 网段。单个 IP 用 /32。" example="192.0.2.0/24"
              onChange={value => edit(name, 'cidrs', value)} />
            <RuleListField label={name === 'company' ? '公司 DNS IPv4' : '个人加密 DNS'} value={group(name).dns}
              hint={name === 'company' ? '每行一个公司提供的 DNS 地址。' : '每行一个 HTTPS DNS 地址，以 /dns-query 结尾。'}
              example={name === 'company' ? '192.0.2.53' : 'https://dns.example.com/dns-query'} onChange={value => edit(name, 'dns', value)} />
          </fieldset>
        </section>)}
      </div>
      <section className="client-card">
        <h2>个人与直连覆盖规则</h2>
        <p>域名后缀可覆盖子域名。添加到草稿后，通过「保存配置」写入。</p>
        <div className="client-actions">
          <select aria-label="覆盖规则类型" value={ruleType} onChange={event => setRuleType(event.target.value)}>
            <option value="DOMAIN">精确域名</option><option value="DOMAIN-SUFFIX">域名后缀</option><option value="IP-CIDR">IPv4 网段</option>
          </select>
          <input aria-label="规则目标" placeholder={ruleType === 'IP-CIDR' ? '192.0.2.0/24' : 'example.org'} value={ruleValue}
            onChange={event => setRuleValue(event.target.value)} />
          <select aria-label="覆盖规则出口" value={ruleTarget} onChange={event => setRuleTarget(event.target.value)}>
            <option value="personal">个人代理</option><option value="direct">直连</option><option value="reject">阻断</option>
          </select>
          <button disabled={!validDraft || !ruleValue.trim() || savingPolicy} onClick={() => {
            const next = { type: ruleType, value: ruleValue.trim(), target: ruleTarget }
            updatePolicyText(pretty({ ...document, personal_rules: editingRule === null ? [...rules, next] : rules.map((rule, i) => i === editingRule ? next : rule) }))
            setRuleValue(''); setEditingRule(null)
          }}>{editingRule === null ? '添加到草稿' : '更新草稿规则'}</button>
        </div>
        {!!rules.length && <ul className="client-list-scroll" aria-label="个人与直连覆盖规则" tabIndex={0}>
          {rules.map((rule, i) => <li key={i}>{String(rule.type)} · {String(rule.value)} → {String(rule.target)}{' '}
            <button onClick={() => {
              setRuleType(String(rule.type)); setRuleTarget(String(rule.target)); setRuleValue(String(rule.value)); setEditingRule(i)
            }}>编辑</button>{' '}
            <button disabled={savingPolicy} onClick={() => {
              updatePolicyText(pretty({ ...document, personal_rules: rules.filter((_, index) => index !== i) }))
              setEditingRule(null); setRuleValue('')
            }}>删除</button>
          </li>)}
        </ul>}
      </section>
      <section className="client-card">
        <h2>已保存基础规则计划</h2>
        <p>办公/家庭覆盖与草稿编辑不代表运行时授权。</p>
        <div className="client-actions">
          <input aria-label="解释目标" placeholder="输入域名或 IP" value={target} onChange={event => setTarget(event.target.value)} />
          <button disabled={!target.trim()} onClick={() => { void read({ action: 'explain', target: target.trim() }) }}>解释已保存基础规则</button>
        </div>
        <div className="client-table-scroll" key={config?.offset} tabIndex={0} role="region" aria-label="已保存规则列表">
          <table className="client-table">
            <thead><tr><th scope="col">类型</th><th scope="col">目标</th><th scope="col">出口</th><th scope="col">来源</th></tr></thead>
            <tbody>{config?.rules.map((rule, i) => <tr key={i}><td>{rule.type}</td><td>{rule.value}</td><td>{rule.target}</td>
              <td>{rule.source}{rule.guard ? ' · 保护' : ''}</td></tr>)}</tbody>
          </table>
        </div>
        <div className="client-pagination">
          <span>{config?.total ? `${config.offset + 1}–${config.offset + config.rules.length} / ${config.total} 条规则` : '暂无规则'}</span>
          <div className="client-actions">
            <button disabled={!config || config.offset === 0} onClick={() => { if (config) loadRules(Math.max(0, config.offset - config.limit)) }}>上一页</button>
            <button disabled={!config || config.offset + config.rules.length >= config.total} onClick={() => { if (config) loadRules(config.offset + config.limit) }}>下一页</button>
            <button onClick={refreshInventory}>刷新规则</button>
          </div>
        </div>
      </section>
    </>}
    {page === 'settings' && <>
      <section className="client-card"><h2>公司入口与直连 DNS</h2><div className="client-actions"><label>本地代理端口<input type="number" min={1024} max={65535} value={Number(group('ports').proxy??7890)} onChange={e=>edit('ports','proxy',Number(e.target.value))}/></label><label>本地 DNS 端口<input type="number" min={1} max={65535} value={Number(group('ports').dns??1053)} onChange={e=>edit('ports','dns',Number(e.target.value))}/></label></div><label>VPN HTTPS 入口<input value={String(group('vpn').server??'')} onChange={e=>edit('vpn','server',e.target.value)}/></label><label>VPN IPv4 引导地址<input value={String(group('vpn').endpoint_ipv4??'')} onChange={e=>edit('vpn','endpoint_ipv4',e.target.value)}/></label><RuleListField label="直连 DNS" value={document.direct_dns} example="https://dns.example.com/dns-query" onChange={value=>updatePolicyText(pretty({...document,direct_dns:value}))}/></section>
      <ProbeEditor rows={Array.isArray(document.probes)?document.probes.filter(isRecord):[]} onChange={rows=>updatePolicyText(pretty({...document,probes:rows}))}/>
      <details className="client-card client-details"><summary>高级策略与版本历史</summary><label>新配置初始化来源<select value={initializeMode} onChange={e=>setInitializeMode(e.target.value as 'policy'|'bootstrap')}><option value="policy">当前策略草稿</option><option value="bootstrap">引导 JSON 文档</option></select></label>{initializeMode==='bootstrap'&&<label>引导文档<textarea className="client-json" value={bootstrap} onChange={e=>setBootstrap(e.target.value)} spellCheck={false}/></label>}<label>高级策略 JSON<textarea className="client-json" value={policyText} onChange={e=>updatePolicyText(e.target.value)} spellCheck={false}/></label><div className="client-actions"><button onClick={()=>{void read({action:'document'})}}>重新读取（替换草稿）</button><button onClick={()=>{void read({action:'validate',policy_json:policyText})}}>校验草稿</button><button onClick={()=>{void read({action:'diff',policy_json:policyText})}}>预览差异</button><button disabled={busy||!canControl} onClick={()=>{void command(initializeMode==='policy'?{action:'initialize',policy_json:policyText}:{action:'initialize',bootstrap_json:bootstrap})}}>初始化新配置</button><button onClick={()=>{void read({action:'history'})}}>版本历史</button></div><label>待回滚 revision<input value={rollback} onChange={e=>setRollback(e.target.value)}/></label><button disabled={busy||!canControl||!rollback||!revision} onClick={()=>{void command({action:'rollback',revision:rollback,expected_revision:revision})}}>回滚到指定版本</button></details>
      {page === 'settings' && !windowsClient && <section className="client-card">
        <h2>配置目录</h2><button disabled={busy || workspaceActivity !== false} onClick={() => { void chooseProfile() }}>选择本机配置目录</button>
        <div className="client-grid">{([
          ['办公', 'office_overrides'], ['家庭', 'home_overrides'],
        ] as const).map(([title, key]) => <OverrideEditor key={key} title={title} value={pretty(document[key] ?? [])}
          onChange={value => updatePolicyText(pretty({ ...document, [key]: JSON.parse(value) }))} />)}</div>
        <p>覆盖规则写入策略草稿，使用「保存配置」保存。</p>
      </section>}
      {page==='settings'&&windowsClient&&<section className="client-card"><h2>工作环境与启动设置</h2><button disabled={busy} onClick={()=>{void chooseProfile()}}>选择本机配置目录</button><button disabled={busy} onClick={()=>{void restoreDefaultProfile()}}>恢复默认配置目录</button><p>仅当当前目录明确未登记时，可接回服务已登记的默认目录与现有运行；此操作不修改通道或环境设置。</p><label><input type="checkbox" checked={false} disabled/>自动连接暂不可用（保持关闭）</label><label>当前环境<select value={environment} onChange={e=>setEnvironment(e.target.value as 'office'|'home')}><option value="home">家庭</option><option value="office">办公</option></select></label><div className="client-grid"><OverrideEditor title="办公" value={officeRules} onChange={setOfficeRules}/><OverrideEditor title="家庭" value={homeRules} onChange={setHomeRules}/></div><p>覆盖规则只能使用 personal 或 direct，不改变公司精确授权优先级。</p><button disabled={busy||!canControl||!snapshot?.settings} onClick={applySettings}>保存启动与环境设置</button><p>会话由后台加密保存，最多复用两小时；密码/OTP 不保存。实际认证状态以服务挑战为准。</p></section>}
    </>}
    {page==='nodes'&&<><h1>个人节点与订阅来源</h1><div className="client-actions"><button disabled={busy||!canControl} onClick={()=>{void importNodes()}}>选择并导入节点文件</button><button disabled={busy||!canControl} onClick={()=>{void command({action:'sync'})}}>同步已配置来源</button></div>
      <NodeInventory nodes={nodes} savedNode={savedNode} channel={snapshot?.personal} load={loadNodes} refresh={refreshInventory} />
      <details className="client-card client-details"><summary>来源配置</summary><p>来源状态：{subscriptions?.configured?'已配置':subscriptions?'尚未配置':'未确认'} · 缓存：{subscriptions?.cache_available?'可用':'未确认'}</p><ul>{subscriptions?.sources.map(source=><li key={source.id}>{source.id} · {source.kind} · {source.state}</li>)}</ul><SourceEditor value={sources} onChange={setSources}/><label>高级来源 JSON<textarea className="client-json" value={sources} onChange={e=>setSources(e.target.value)} spellCheck={false}/></label>{sourcesPresent&&<p>此配置已有来源，现有链接不回显。保存将用本次输入替换来源。</p>}{sourcesPresent&&<label><input type="checkbox" checked={sourceReplacement} onChange={e=>setSourceReplacement(e.target.checked)}/>确认替换现有来源</label>}<button disabled={busy||!canControl||!revision||!sources.trim()||sourcesPresent&&!sourceReplacement} onClick={()=>{void command({action:'sources_save',sources_json:sources,expected_revision:revision})}}>校验并保存来源</button></details>
    </>}
    {page==='diagnostics'&&<><h1>诊断、版本与恢复</h1>
      {connectionControl && <section className="client-card">
        <h2>通道检查详情</h2>
        <ConnectionChannels snapshot={snapshot} details />
        {windowsClient && <p>公司 IPv6：{snapshot?.company.ipv6_state === 'blocked' ? '已由服务确认阻断' : '阻断待验证'}</p>}
      </section>}
      <section className="client-card"><h2>环境检查</h2><button disabled={checking} onClick={checkEnvironment}>{checking?'检查中…':'检查运行环境'}</button><ul>{environmentCheck?.checks.map(item=><li key={item.id}>{item.label} · {item.state} · {item.message}</li>)}</ul><button onClick={showRecovery}>显示独立恢复入口</button></section><div className="client-actions">{(['runtime','version','diagnostics','cleanup_preview','history'] as const).map(action=><button key={action} onClick={()=>{void read({action})}}>{({runtime:'运行时检查',version:'版本与能力',diagnostics:'脱敏诊断导出',cleanup_preview:'运行清理预览',history:'配置历史'})[action]}</button>)}</div>{macosClient && <MacRecovery snapshot={snapshot} busy={busy || !canControl}
      recover={() => { void submit({ kind: 'exit_restore', stop: {} }) }} />}
      {windowsClient&&<section className="client-card"><h2>精确运行恢复</h2><p>恢复要求：{snapshot?.recovery_required?'需要恢复':'以后台证据为准'}；恢复确认：{snapshot?.restored?'已确认':'未确认'}</p><button disabled={!canControl||busy&&(operation?.kind==='takeover_stop'||operation?.kind==='exit_restore')} onClick={()=>{void submit({kind:'takeover_stop',stop:{}})}}>停止并恢复</button><label>清理预览中的运行 ID<input value={cleanupID} onChange={e=>setCleanupID(e.target.value)}/></label><button disabled={busy||!canControl||!cleanupID} onClick={()=>{void command({action:'cleanup',opaque_run_id:cleanupID})}}>清理预览对应运行</button></section>}</>}
    {result?.page === page && <section className="client-card"><h2>操作结果</h2><pre className="client-result" tabIndex={0}>{pretty(result.value)}</pre></section>}
  </section>
}
