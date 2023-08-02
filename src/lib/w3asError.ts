// RFC 7807 - Problem Details for HTTP APIs
export interface ProblemDetail {
  type: string;
  title: string;
  status: number;
  detail: string;
}

export default class W3asError<PD extends ProblemDetail> extends Error {
  readonly name: string;
  readonly message: string;
  readonly problemDetail: PD;
  readonly sourceError: unknown;

  constructor(problemDetail: PD, sourceError?: unknown) {
    super();
    this.name = this.constructor.name;
    this.message = problemDetail.detail;
    this.problemDetail = problemDetail;
    this.sourceError = sourceError;
  }
}
