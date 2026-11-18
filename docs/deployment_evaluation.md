# Deployment evaluation

Every result below was observed against the docker daemon: the image of
the artifact was built, the container was started beside the running
version and the traffic was shifted through nginx. The tables are
generated from the outcomes the scenarios observed, so they cannot drift
away from them.

## Tamper: a signed artifact that was changed

Each case below changed the artifact or its signature after the signing.
The engine recomputed every file hash, the root hash, the signature and
the link to the audit log, and refused the deployment.

| Tamper | Refused | Reason | Logged event |
| --- | --- | --- | --- |
| a file changed after the signing | yes | the file 'pkg/overtime.py' does not match its pinned hash | deployment_refused |
| the signature was swapped | yes | the signature does not verify against the public key | deployment_refused |
| the wrong public key was used | yes | the signature does not verify against the public key | deployment_refused |
| a pinned file was missing | yes | the file 'pkg/overtime.py' is missing | deployment_refused |
| the audit log head did not match | yes | the audit log does not hold the signed head 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' | deployment_refused |

## Rollout: the traffic shifts in steps

The rollout ended with the status 'deployed'. The version that carried
the traffic before the rollout was retired.

| Traffic | Requests | Errors | Error rate |
| --- | --- | --- | --- |
| 10% | 100 | 0 | 0.0000 |
| 50% | 100 | 0 | 0.0000 |
| 100% | 100 | 0 | 0.0000 |

## Rollback: the new version fails

The status of the deployment was 'rolled_back'. The event
'deployment_rolled_back' was written to the audit log with the reason
'the error rate of the new version was 1.0000 at 10% traffic, above the
threshold of 0.0000'. The version that carried the traffic again was the
one that was running before the rollout.

## Zero downtime: the requests during the rollout

A steady stream of requests ran against the router while the traffic was
shifted. None of them failed.

| Traffic | Requests | Errors | Error rate |
| --- | --- | --- | --- |
| 10% | 100 | 0 | 0.0000 |
| 50% | 100 | 0 | 0.0000 |
| 100% | 100 | 0 | 0.0000 |
