declare module 'pg' {
  export interface QueryResult<T = Record<string, unknown>> { rows: T[]; rowCount: number | null }
  export interface PoolClient { query<T = Record<string, unknown>>(text: string, values?: unknown[]): Promise<QueryResult<T>>; release(): void }
  export class Pool {
    constructor(config?: { connectionString?: string; max?: number; connectionTimeoutMillis?: number; idleTimeoutMillis?: number; application_name?: string; ssl?: boolean | { rejectUnauthorized?: boolean } });
    query<T = Record<string, unknown>>(text: string, values?: unknown[]): Promise<QueryResult<T>>;
    connect(): Promise<PoolClient>;
    end(): Promise<void>;
  }
}
