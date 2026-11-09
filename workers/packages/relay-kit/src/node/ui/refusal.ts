/**
 * The local page's refusals: an HTTP status, one closed code the page words for the operator, the form field it
 * belongs to (if any) and at most a member path. Never a value: a refusal can be about a credential.
 */
export class UiRefusal extends Error {
  override readonly name = "UiRefusal";
  readonly status: number;
  readonly code: string;
  readonly field: string | null;
  /** A member path or a closed sub-code (`accounts.3.egress`, `device_code_expired`); never a value. */
  readonly detail: string | null;

  constructor(status: number, code: string, field: string | null = null, detail: string | null = null) {
    super(`ui/${code}${field === null ? "" : ` (${field})`}`);
    this.status = status;
    this.code = code;
    this.field = field;
    this.detail = detail;
  }
}
