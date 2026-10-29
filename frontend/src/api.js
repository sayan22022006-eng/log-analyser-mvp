const API = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, options)
  if (!response.ok) {
    let message = `Request failed (${response.status})`
    try {
      const body = await response.json()
      message = body.detail || message
    } catch {}
    throw new Error(message)
  }
  if (response.status === 204) return null
  return response
}

export async function uploadScan(file) {
  const body = new FormData()
  body.append('file', file)
  return (await request('/api/scans', { method: 'POST', body })).json()
}
export async function getScans() {
  return (await request('/api/scans')).json()
}
export async function getScan(id) {
  return (await request(`/api/scans/${id}`)).json()
}
export async function getAlerts(id, filters = {}) {
  const params = new URLSearchParams()
  Object.entries(filters).forEach(([k, v]) => { if (v) params.set(k, v) })
  return (await request(`/api/scans/${id}/alerts?${params}`)).json()
}
export async function deleteScan(id) {
  return request(`/api/scans/${id}`, { method: 'DELETE' })
}
export function exportUrl(id) {
  return `${API}/api/scans/${id}/export?format=csv`
}
export async function getDashboard() {
  return (await request('/api/dashboard')).json()
}
