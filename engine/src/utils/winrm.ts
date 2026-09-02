// Minimal WinRM client for invoking PowerShell commands on a Windows host.
// Uses WinRM over HTTP/HTTPS (SOAP protocol) — no external dependencies.
// Implements: CreateShell → ExecuteCommand → ReceiveOutput → DeleteShell

import { request as httpRequest } from 'http'
import { request as httpsRequest } from 'https'

export interface WinRmOptions {
  host:     string
  port:     number
  useSSL:   boolean
  username: string
  password: string
  skipCertCheck?: boolean
  timeoutMs?: number
}

export interface WinRmResult {
  stdout:   string
  stderr:   string
  exitCode: number
}

// ── SOAP envelope templates ───────────────────────────────────────────────────

const NS = {
  env:  'http://www.w3.org/2003/05/soap-envelope',
  a:    'http://schemas.xmlsoap.org/ws/2004/08/addressing',
  w:    'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd',
  p:    'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd',
  rsp:  'http://schemas.microsoft.com/wbem/wsman/1/windows/shell',
  xsi:  'http://www.w3.org/2001/XMLSchema-instance',
}

function uuid(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16)
  })
}

function soapHeader(action: string, to: string, msgId: string, shellId?: string): string {
  const refParam = shellId
    ? `<w:SelectorSet><w:Selector Name="ShellId">${shellId}</w:Selector></w:SelectorSet>`
    : ''
  return `<env:Header>
    <a:To>${to}</a:To>
    <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
    <a:Action mustUnderstand="true">${action}</a:Action>
    <a:MessageID>uuid:${msgId}</a:MessageID>
    <w:Locale mustUnderstand="false" xml:lang="en-US"/>
    <p:DataLocale mustUnderstand="false" xml:lang="en-US"/>
    <w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize>
    <w:OperationTimeout>PT${Math.floor((60000) / 1000)}S</w:OperationTimeout>
    ${refParam}
  </env:Header>`
}

function envelope(header: string, body: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="${NS.env}" xmlns:a="${NS.a}" xmlns:w="${NS.w}"
              xmlns:p="${NS.p}" xmlns:rsp="${NS.rsp}" xmlns:xsi="${NS.xsi}">
  ${header}
  <env:Body>${body}</env:Body>
</env:Envelope>`
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

function post(opts: WinRmOptions, body: string): Promise<string> {
  const cred = Buffer.from(`${opts.username}:${opts.password}`).toString('base64')
  const headers: Record<string, string> = {
    'Content-Type':   'application/soap+xml;charset=UTF-8',
    'Content-Length': Buffer.byteLength(body).toString(),
    'Authorization':  `Basic ${cred}`,
  }

  return new Promise((resolve, reject) => {
    const req = (opts.useSSL ? httpsRequest : httpRequest)(
      {
        hostname:           opts.host,
        port:               opts.port,
        path:               '/wsman',
        method:             'POST',
        headers,
        timeout:            opts.timeoutMs ?? 60_000,
        rejectUnauthorized: !(opts.skipCertCheck ?? true),
      },
      res => {
        let data = ''
        res.on('data', (chunk: Buffer) => { data += chunk.toString() })
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 400) {
            reject(new Error(`WinRM HTTP ${res.statusCode}: ${data.slice(0, 300)}`))
          } else {
            resolve(data)
          }
        })
      }
    )
    req.on('error', reject)
    req.on('timeout', () => { req.destroy(); reject(new Error('WinRM request timed out')) })
    req.write(body)
    req.end()
  })
}

// ── XML extraction helpers ────────────────────────────────────────────────────

function extractTag(xml: string, tag: string): string | null {
  const re = new RegExp(`<[^>]*:?${tag}[^>]*>([\\s\\S]*?)<\\/[^>]*:?${tag}>`, 'i')
  const m = xml.match(re)
  return m ? m[1].trim() : null
}

function decodeBase64(s: string): string {
  return Buffer.from(s, 'base64').toString('utf-8')
}

// ── WinRM protocol steps ──────────────────────────────────────────────────────

async function createShell(opts: WinRmOptions, toUrl: string): Promise<string> {
  const msgId = uuid()
  const body = envelope(
    soapHeader('http://schemas.xmlsoap.org/ws/2004/09/transfer/Create', toUrl, msgId),
    `<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>`
  )
  const resp = await post(opts, body)
  // Try alternate extraction
  const m = resp.match(/<[^>]*Selector[^>]*Name="ShellId"[^>]*>([^<]+)</)
  const id = m ? m[1] : extractTag(resp, 'ShellId')
  if (!id) throw new Error('WinRM: could not extract ShellId from CreateShell response')
  return id
}

async function executeCommand(opts: WinRmOptions, toUrl: string, shellId: string, command: string): Promise<string> {
  const msgId = uuid()
  const escaped = command.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
  const body = envelope(
    soapHeader('http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command', toUrl, msgId, shellId),
    `<rsp:CommandLine><rsp:Command>${escaped}</rsp:Command></rsp:CommandLine>`
  )
  const resp = await post(opts, body)
  const cmdId = extractTag(resp, 'CommandId')
  if (!cmdId) throw new Error('WinRM: could not extract CommandId')
  return cmdId
}

async function receiveOutput(opts: WinRmOptions, toUrl: string, shellId: string, cmdId: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  let stdout = ''
  let stderr = ''
  let exitCode = -1
  let done = false

  while (!done) {
    const msgId = uuid()
    const body = envelope(
      soapHeader('http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive', toUrl, msgId, shellId),
      `<rsp:Receive><rsp:DesiredStream CommandId="${cmdId}">stdout stderr</rsp:DesiredStream></rsp:Receive>`
    )
    const resp = await post(opts, body)

    // Extract stdout/stderr streams
    const streamRe = /<rsp:Stream\s+Name="(stdout|stderr)"[^>]*>([^<]*)<\/rsp:Stream>/gi
    let m: RegExpExecArray | null
    while ((m = streamRe.exec(resp)) !== null) {
      if (m[2]) {
        if (m[1] === 'stdout') stdout += decodeBase64(m[2])
        else stderr += decodeBase64(m[2])
      }
    }

    // Check for exit code
    const exitMatch = resp.match(/<rsp:ExitCode>(\d+)<\/rsp:ExitCode>/)
    if (exitMatch) {
      exitCode = parseInt(exitMatch[1], 10)
      done = true
    }

    // Check command state
    if (resp.includes('http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done')) {
      done = true
    }
  }

  return { stdout, stderr, exitCode }
}

async function deleteShell(opts: WinRmOptions, toUrl: string, shellId: string): Promise<void> {
  const msgId = uuid()
  const body = envelope(
    soapHeader('http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete', toUrl, msgId, shellId),
    ''
  )
  await post(opts, body).catch(() => { /* best-effort cleanup */ })
}

// ── Public API ────────────────────────────────────────────────────────────────

export async function runWinRmCommand(opts: WinRmOptions, command: string): Promise<WinRmResult> {
  const scheme = opts.useSSL ? 'https' : 'http'
  const toUrl  = `${scheme}://${opts.host}:${opts.port}/wsman`

  const shellId = await createShell(opts, toUrl)
  try {
    const cmdId = await executeCommand(opts, toUrl, shellId, command)
    const result = await receiveOutput(opts, toUrl, shellId, cmdId)
    return result
  } finally {
    await deleteShell(opts, toUrl, shellId)
  }
}
