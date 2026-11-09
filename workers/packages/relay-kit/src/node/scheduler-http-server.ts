/**
 * The scheduler's transport: one `node:http` (or `node:https` for the standalone test/scheduler
 * mode) listener around the pure `SchedulerHandler`. The agent runs the plain-HTTP form; TLS is the
 * relay proxy's job (design v2 §A.10), and `init` writes the nginx/Caddy snippet that does it.
 *
 * The handler owns every protocol decision and every refusal; this file only frames bytes. The body
 * is read up to a cap before the handler sees it, because the signature covers the exact bytes and a
 * streamed body could not be replayed to a second candidate key.
 */
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFileSync } from "node:fs";
import { RelayKitError } from "../errors.ts";
import type { HeaderReader } from "@gray/relay-connector";
import type { SchedulerHandler } from "../scheduler/handler.ts";

/** The largest body the transport buffers; a report batch is the biggest legitimate one (4 MiB). */
export const DEFAULT_MAX_HTTP_BODY_BYTES = 8 * 1024 * 1024;

export interface SchedulerListen {
  readonly host: string;
  readonly port: number;
}

export interface SchedulerTlsFiles {
  readonly certFile: string;
  readonly keyFile: string;
}

export interface StartSchedulerServerOptions {
  readonly listen: SchedulerListen;
  readonly handler: SchedulerHandler;
  /** Absent: plain HTTP (the agent). Present: TLS directly (tests and the legacy standalone mode). */
  readonly tls?: SchedulerTlsFiles;
  readonly maxBodyBytes?: number;
  /**
   * Asked first with the raw request: true when it answered (the relay's own page in public mode, under `/ui/`), false
   * to leave the request to the scheduler as before.
   */
  readonly raw?: (request: IncomingMessage, response: ServerResponse) => Promise<boolean>;
}

export interface StartedSchedulerServer {
  /** The origin actually bound, with the port the OS chose when `listen.port` was 0. */
  readonly url: string;
  readonly port: number;
  close(): Promise<void>;
}

function headerReader(request: IncomingMessage): HeaderReader {
  return {
    get(name: string): string | null {
      const value = request.headers[name.toLowerCase()];
      if (value === undefined) return null;
      return Array.isArray(value) ? value.join(", ") : value;
    },
  };
}

function readBody(request: IncomingMessage, cap: number): Promise<Uint8Array> {
  return new Promise((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > cap) {
        reject(new RelayKitError("io", "request body too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolveBody(new Uint8Array(Buffer.concat(chunks))));
    request.on("error", reject);
  });
}

function writeResponse(response: ServerResponse, status: number, headers: Readonly<Record<string, string>>, body: Uint8Array): void {
  response.writeHead(status, headers);
  response.end(body);
}

/** Start one listener. Resolves once it is accepting connections. */
export function startSchedulerServer(options: StartSchedulerServerOptions): Promise<StartedSchedulerServer> {
  const cap = options.maxBodyBytes ?? DEFAULT_MAX_HTTP_BODY_BYTES;
  const handler = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    try {
      if (options.raw !== undefined && (await options.raw(request, response))) return;
      let path: string;
      try {
        path = new URL(request.url ?? "/", "http://agent").pathname;
      } catch {
        writeResponse(response, 400, { "content-type": "application/json" }, new TextEncoder().encode('{"error":"bad_request"}'));
        return;
      }
      const body = await readBody(request, cap);
      const answer = await options.handler({ method: request.method ?? "GET", path, headers: headerReader(request), body });
      writeResponse(response, answer.status, answer.headers, answer.body);
    } catch {
      if (!response.headersSent) {
        writeResponse(response, 413, { "content-type": "application/json" }, new TextEncoder().encode('{"error":"too_large"}'));
      } else {
        response.destroy();
      }
    }
  };
  const server: Server =
    options.tls === undefined
      ? createHttpServer((request, response) => void handler(request, response))
      : createHttpsServer(
          {
            cert: readFileSync(options.tls.certFile),
            key: (() => {
              // The key is a secret; the standalone transport reads it without echoing it.
              try {
                return readFileSync(options.tls?.keyFile ?? "");
              } catch {
                throw new RelayKitError("io", "cannot read the scheduler TLS key");
              }
            })(),
          },
          (request, response) => void handler(request, response),
        );
  server.on("clientError", (_error, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\n");
  });
  return new Promise<StartedSchedulerServer>((resolveStart, reject) => {
    server.once("error", reject);
    server.listen(options.listen.port, options.listen.host, () => {
      const address = server.address();
      const port = address !== null && typeof address === "object" ? address.port : options.listen.port;
      const scheme = options.tls === undefined ? "http" : "https";
      resolveStart({
        url: `${scheme}://${options.listen.host}:${port}`,
        port,
        close: () =>
          new Promise<void>((resolveClose) => {
            server.close(() => resolveClose());
            server.closeAllConnections();
          }),
      });
    });
  });
}
