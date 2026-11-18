import { useEffect, useState } from 'react'

export const lines = (text: string): string[] => text.split(/[\r\n,]+/).map(line => line.trim()).filter(Boolean)

export function RuleListField({ label, value, example, hint, onChange }: {
  label: string
  value: unknown
  example: string
  hint?: string
  onChange: (value: string[]) => void
}) {
  const saved = Array.isArray(value) ? value.filter(entry => typeof entry === 'string').join('\n') : ''
  const [text, setText] = useState(saved)
  useEffect(() => {
    setText(current => lines(current).join('\n') === saved ? current : saved)
  }, [saved])
  return <label>
    {label}
    {hint && <small className="client-field-hint">{hint}</small>}
    <textarea rows={3} value={text} placeholder={example} spellCheck={false}
      onChange={event => {
        const next = event.target.value
        setText(next)
        onChange(lines(next))
      }} />
  </label>
}
