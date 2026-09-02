export function coraScore(catI: number, catII: number, catIII: number, total: number): number {
  if (total === 0) return 100
  const weighted = (catI * 10) + (catII * 3) + catIII
  return Math.max(0, Math.round(100 - Math.min(100, (weighted / total) * 100)))
}

export function coraRisk(score: number): 'low' | 'medium' | 'high' {
  if (score >= 70) return 'low'
  if (score >= 30) return 'medium'
  return 'high'
}

export function coraColor(score: number): string {
  const risk = coraRisk(score)
  return risk === 'low' ? '#22c55e' : risk === 'medium' ? '#f59e0b' : '#ef4444'
}
