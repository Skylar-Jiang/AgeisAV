# Analyst case admission v1 — frozen before new PE scanning

Policy: `analyst-case-admission-v1`. Implemented by `experiments/label_admission.py`.

This policy establishes operational confidence, not absolute truth. Existing source-only
unknown labels remain unknown until evidence is reviewed. No detector vote, AegisAV
prediction, signature validity or MalwareBazaar origin alone supplies an independent label.
The function validates audit-record completeness and consistency. It cannot authenticate
the truthfulness of supplied review assertions; actual source review and raw verification
must produce the records. A human method flag does not mean this software performed human review.

## Malicious candidate grades

- **unknown:** exact SHA technical evidence is absent; dual-use, family/source conflict
  remains; or available raw file fails SHA/integrity/strict-PE verification.
- **probable:** a primary analyst technical report associates the exact SHA with a
  specific malicious purpose, but raw integrity/PE verification or review is incomplete.
- **high-confidence:** the exact primary report evidence, specific behavior, original
  SHA/strict PE checks and recorded accepted review are all present; ambiguities cleared.
  Automated research review is explicitly recorded as automated, never human approval.

Accepted behavior categories: credential exfiltration, backdoor command channel,
unauthorized payload loader, destructive wiper, ransomware encryption. Campaign IoC
presence alone is insufficient: benign side-loading hosts and administrative utilities
must not inherit the campaign's malicious label. Family disagreement is quarantined
until adjudicated; binary maliciousness and family attribution are separately reviewed.

For each case retain source URLs, primary report locator, reviewer/method/status/time,
behavior paraphrase, reported architecture/family, source/global date distinction,
acquisition journal, original SHA and PE check, exact/near/training overlap and exclusions.
Never put raw files, candidate lists or private labels in the public source snapshot.

## Uses and split restrictions

High-confidence cases with automated review may enter **exploratory paired analysis**,
with grade, source-selection bias, review method and overlap limitations disclosed.
They do not automatically enter formal final evaluation.

Formal final admission additionally requires recorded human acceptance, a final-candidate
role, no observed detector results, a frozen split before scanning, cleared training and
near-duplicate overlap, and verified temporal eligibility. Unknown gates fail closed.
Never promote already observed development cohorts into a final set. Labels can be
corrected with revisions; that does not erase previous observation or create independence.

There is no guarantee that 100/300 cases represent unseen families. Aggregate by source,
family, architecture, time and clusters; report failures/abstentions outside negative counts.

## Benign candidates

Use multiple publisher-operated distribution channels with HTTPS, retained package
SHA/headers, unmodified member SHA, signature evidence when available, and manual
purpose/provenance review. Signature or official hosting alone is a benign proxy.
Administrative/dual-use tools get a separate policy stratum. Source-build provenance
may add evidence but must not be fabricated from an absent reproducible build.
Formal final admission has the same human/split/training/near/time gates.

## Frozen assets

This admission protocol does not change any hash reference, YARA rule, model, operating
threshold or fusion policy. No case SHA is added to the detection database. Any rule
research uses a separate validation development asset version; final results cannot choose it.
