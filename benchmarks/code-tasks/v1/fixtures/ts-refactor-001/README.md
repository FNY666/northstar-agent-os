# Task fixture

Preserve `Client(baseUrl).get(path)` and `ResponsePayload {status:number,body:string}`. Add an injectable `Transport.request(url)` and a default `FetchTransport`. Tests must exercise injection without making network requests.

Run public checks with `node --test tests/contract.test.ts` on Node 24.
