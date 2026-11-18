# Knowledge evaluation

Every result below was observed against the live container of Qdrant and
against the code of the engine itself. The graphs are built from the
sources of the attendance module, the retrieval is measured on the
points that were written and the memory of a deployment is measured on
the audit event it left. The tables are generated from those outcomes,
so they cannot drift away from them.

## The repository graph

The sources are parsed, never executed. The graph names the files of the
workspace, the classes and functions they define, the imports between
them, the calls inside them and the tests that exercise them.

| Kind | Nodes |
| --- | --- |
| artifact | 1 |
| class | 2 |
| file | 3 |
| function | 3 |
| test | 1 |

| Edge | Count |
| --- | --- |
| calls | 1 |
| defines | 8 |
| imports | 3 |
| produced_by | 3 |
| tests | 2 |

The impact analysis answers the question which files are affected if a
file changes. A change of 'pkg/attendance.py' affects:
pkg/attendance.py, tests/test_attendance.py.

## The domain graph

The entities and the relations come from the specification of the
requirement. The code that implements an entity is linked to it, so that
the graph answers both what belongs together and where it lives.

| Entity | Relation | Implemented in |
| --- | --- | --- |
| Attendance | Attendance belongs_to Employee, Punch references Attendance | pkg/attendance.py |
| Employee | Attendance belongs_to Employee | pkg/employee.py |
| Punch | Punch references Attendance | - |

## The vector store

Every point carries the tenant that owns it. The query always carries
the tenant as well, so a tenant never reads the points of another
tenant. The id of a point comes from the hash of the artifact, so
writing the same artifact again replaces the point instead of
duplicating it.

| Observation | Result |
| --- | --- |
| points of the owner tenant | 1 |
| points of the other tenant | 0 |
| hits of the owner tenant | 1 |
| hits of the other tenant | 0 |
| the id of a repeated write stays the same | yes |
| points after the second write | 1 |

## The retrieval service

The retrieval is read only, redacted and limited. Every answer is
wrapped as untrusted data, so that a poisoned document of the store
cannot act as an instruction. The test designer does not see the code of
the running task until its test suite is frozen.

| Observation | Result |
| --- | --- |
| a secret is removed from the text | yes |
| personal data is removed from the text | yes |
| an injection stays inside the wrapper | yes |
| wrappers in the context | 2 |
| items of one answer | 2 |
| items of an answer that asks for three | 2 |
| items the test designer sees before the freeze | 1 |
| items the test designer sees after the freeze | 2 |
| items the coder sees | 2 |

## The memory of a deployment

Only a deployment that was verified and signed teaches the engine
something. The writer stores a short summary of the run, indexes the
code of the artifact, rebuilds the repository graph and writes the ids
and the hashes of the write into the audit log. Work that was refused or
that was never signed never reaches the store.

| Observation | Result |
| --- | --- |
| points in the episodic memory | 1 |
| points in the repository index | 5 |
| audit event of the write | qdrant_updated |
| points of an unsigned deployment | 0 |
| summary of the run | Task type: feature; What worked: the sandbox run passed 3 tests; What failed: the first attempt failed on the holiday rule; Artifact hash: 8421fb1795c10c72cff50348dffc2d37e59fd253bdd1dd63f16fb5702821b7c6 |
| graph of the artifact | repo.json |

## The conversation store

Every model call leaves a record. The text of the exchange is redacted
and kept in files that the record references by their hash, so the audit
log holds the hashes and never the text itself.

| Field of the record | Kept |
| --- | --- |
| attempt | yes |
| call_id | yes |
| completion_tokens | yes |
| correlation_id | yes |
| latency_ms | yes |
| metadata | yes |
| model | yes |
| model_version | yes |
| parameters | yes |
| prompt_hash | yes |
| prompt_tokens | yes |
| response_hash | yes |
| role | yes |
| run_id | yes |
| tenant_id | yes |
| timestamp | yes |
| total_tokens | yes |

The record of the call holds 30 tokens and the text of the prompt is
redacted: yes.
