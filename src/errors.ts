/**
 * WardenError — structured error for Warden auth.
 */
export class WardenError extends Error {
  readonly code: string
  readonly hint?: string

  constructor(code: string, message: string, options?: { hint?: string }) {
    super(message)
    this.name = 'WardenError'
    this.code = `WARDEN_${code}`
    this.hint = options?.hint
  }
}
