import type { ReactNode } from 'react'

export function WorkspaceStatus({ label, running, problem, children }: {
  label: string
  running: boolean
  problem: boolean
  children: ReactNode
}) {
  return <details className="workspace-status" onKeyDown={event => {
    if (event.key === 'Escape' && event.currentTarget.open) {
      event.currentTarget.open = false
      event.currentTarget.querySelector('summary')?.focus()
    }
  }}>
    <summary aria-label="工作空间状态">
      <span className={`workspace-status-dot${problem ? ' problem' : running ? ' running' : ''}`} aria-hidden="true" />
      <span role="status">{label}</span>
    </summary>
    <div className="workspace-status-panel">{children}</div>
  </details>
}
