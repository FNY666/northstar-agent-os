export interface ResponsePayload {status: number; body: string}
export class Client {
  private baseUrl: string;
  constructor(baseUrl: string) { this.baseUrl = baseUrl; }
  async get(path: string): Promise<ResponsePayload> {
    const response = await fetch(this.baseUrl + "/" + path);
    return {status: response.status, body: await response.text()};
  }
}
