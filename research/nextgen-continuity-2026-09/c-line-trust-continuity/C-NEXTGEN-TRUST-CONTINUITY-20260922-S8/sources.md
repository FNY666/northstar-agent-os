# Sources and claim boundaries

All URLs below are public official documentation references captured as source pointers. S8 did not call these services or use their SDKs; documentation support is separate from synthetic execution. Access status in this offline package is `unverified` unless a direct text statement is recorded from the official page; no source content is copied as if it were a live test.

| source_id | Publisher | Official URL | Supports | evidence_status |
|---|---|---|---|---|
| K8S-API-CONCEPTS | Kubernetes project | https://kubernetes.io/docs/reference/using-api/api-concepts/ | Resource versions and optimistic concurrency / conflict handling concepts | confirmed |
| AWS-S3-CONDITIONAL | Amazon Web Services | https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-requests.html | Conditional requests using validators such as ETag and conditional outcomes | confirmed |
| AWS-S3-ERRORS | Amazon Web Services | https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html | S3 error status reference; preserve operation/context for 409/412 interpretation | confirmed |
| GCS-PRECONDITIONS | Google Cloud | https://cloud.google.com/storage/docs/generations-preconditions | Generation/metageneration preconditions and failed-precondition behavior | confirmed |
| AZURE-CONCURRENCY | Microsoft Azure | https://learn.microsoft.com/en-us/azure/storage/blobs/concurrency-manage | Blob ETag optimistic concurrency and conditional requests | confirmed |
| AZURE-LEASES | Microsoft Azure | https://learn.microsoft.com/en-us/rest/api/storageservices/lease-blob | Blob lease conditions and lease-related status behavior | confirmed |
| HTTP-SEMANTICS | IETF | https://www.rfc-editor.org/rfc/rfc9110.html | General HTTP method/status semantics; not a cloud consistency or durability guarantee | confirmed |

## Source limitations

- Documentation may describe a platform contract or error surface; it does not prove a particular deployment, SDK version, network path, cache, or durability outcome.
- S8 intentionally did not use browser/network access. Therefore no claim is made that pages were reachable at run time; a future review should pin retrieval date/version and quote exact clauses before upgrading documentation-led statuses.
- `confirmed` above means “bounded by the cited official documentation topic,” not “verified by a live platform call.”
- Any conflict between a raw status and operation-specific cause is retained as `conflicting` or `unverified` in the ledger rather than normalized away.
