/**
 * Dependency-free Node consumer for Northstar's experimental local app-server.
 *
 * This is deliberately a client only: a host still owns the Python runtime,
 * provider, workspace, policy and Unix socket. It is not an npm package or a
 * replacement for host authorization.
 */
import crypto from "node:crypto";
import net from "node:net";

export const APP_PROTOCOL = "northstar.agent-app.v1";
export const MAX_FRAME_BYTES = 1024 * 1024;
export const DEFAULT_WAIT_MS = 10_000;
export const MAX_WAIT_MS = 30_000;

const RESERVED_FIELDS = new Set(["protocol", "op", "request_id", "actor_id", "auth"]);

/** Sort object keys recursively, matching Python json.dumps(sort_keys=True, ensure_ascii=False). */
export function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) {
    throw new TypeError("undefined is not canonical JSON");
  }
  return encoded;
}

export function hmacFor(payload, secret) {
  const key = Buffer.isBuffer(secret) ? secret : Buffer.from(secret);
  return `hmac-sha256:${crypto.createHmac("sha256", key).update(canonicalJson(payload), "utf8").digest("hex")}`;
}

function withoutAuth(payload) {
  const unsigned = { ...payload };
  delete unsigned.auth;
  return unsigned;
}

function equalMac(left, right) {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function remoteError(error) {
  const failure = new Error(String(error?.message ?? "app-server request failed"));
  failure.code = String(error?.code ?? "remote_error");
  failure.details = error;
  return failure;
}

export class AppServerClient {
  constructor(socketPath, { secret, timeoutMs = 5_000 } = {}) {
    if (typeof socketPath !== "string" || !socketPath.startsWith("/")) {
      throw new TypeError("socketPath must be an absolute Unix socket path");
    }
    const channelSecret = Buffer.isBuffer(secret) ? secret : Buffer.from(secret ?? "", "utf8");
    if (channelSecret.length < 16) {
      throw new TypeError("secret must be at least 16 bytes");
    }
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError("timeoutMs must be a positive integer");
    }
    this.socketPath = socketPath;
    this.secret = channelSecret;
    this.timeoutMs = timeoutMs;
  }

  async call(operation, { requestId, actorId, ...fields } = {}) {
    const reserved = Object.keys(fields).filter((key) => RESERVED_FIELDS.has(key));
    if (reserved.length > 0) {
      throw new TypeError(`reserved wire fields cannot be overridden: ${reserved.sort().join(", ")}`);
    }
    const request = {
      protocol: APP_PROTOCOL,
      op: operation,
      request_id: requestId,
      actor_id: actorId,
      ...fields,
    };
    request.auth = hmacFor(request, this.secret);
    const response = await this.#exchange(`${JSON.stringify(request)}\n`);
    if (response?.protocol !== APP_PROTOCOL) {
      throw new Error("app-server response protocol is invalid");
    }
    if (typeof response.auth !== "string" || !equalMac(response.auth, hmacFor(withoutAuth(response), this.secret))) {
      throw new Error("app-server response HMAC is invalid");
    }
    if (response.request_id !== requestId) {
      throw new Error("app-server response request_id does not match");
    }
    if (!response.ok) {
      throw remoteError(response.error);
    }
    return response;
  }

  async start({ requestId, actorId, prompt }) {
    return this.call("run.start", { requestId, actorId, prompt });
  }

  async status({ requestId, actorId, runId }) {
    return this.call("run.status", { requestId, actorId, run_id: runId });
  }

  async events({ requestId, actorId, runId, fromSequence = 0, limit = 256 }) {
    return this.call("run.events", {
      requestId,
      actorId,
      run_id: runId,
      from_sequence: fromSequence,
      limit,
    });
  }

  async wait({ requestId, actorId, runId, timeoutMs = DEFAULT_WAIT_MS }) {
    return this.call("run.wait", {
      requestId,
      actorId,
      run_id: runId,
      timeout_ms: timeoutMs,
    });
  }

  async cancel({ requestId, actorId, runId }) {
    return this.call("run.cancel", { requestId, actorId, run_id: runId });
  }

  #exchange(line) {
    const payload = Buffer.from(line, "utf8");
    if (payload.length > MAX_FRAME_BYTES) {
      return Promise.reject(new Error("app-server request exceeds the frame bound"));
    }
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ path: this.socketPath });
      let chunks = [];
      let total = 0;
      let settled = false;
      const fail = (error) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        reject(error);
      };
      socket.setTimeout(this.timeoutMs, () => fail(new Error("app-server response timed out")));
      socket.once("error", (error) => fail(error));
      socket.on("data", (chunk) => {
        if (settled) return;
        chunks.push(chunk);
        total += chunk.length;
        if (total > MAX_FRAME_BYTES) {
          fail(new Error("app-server response exceeds the frame bound"));
          return;
        }
        const data = Buffer.concat(chunks);
        const newline = data.indexOf(0x0a);
        if (newline < 0) return;
        settled = true;
        socket.end();
        try {
          resolve(JSON.parse(data.subarray(0, newline).toString("utf8")));
        } catch (error) {
          reject(new Error(`invalid app-server JSON response: ${error.message}`));
        }
      });
      socket.once("connect", () => socket.write(payload));
    });
  }
}
