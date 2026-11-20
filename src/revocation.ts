// Copyright 2026 The Casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * RevocationResultCategory classifies the outcome of a single named-policy
 * revocation so an operator can tell "the rule was never there" apart from
 * "storage refused the write" and "the revocation is fully applied".
 */
export enum RevocationResultCategory {
  // The named rule does not exist in the in-memory policy; nothing was written.
  PolicyNotFound = 'PolicyNotFound',
  // The adapter accepted the write and the rule is no longer in effect.
  Revoked = 'Revoked',
  // The adapter refused the write. The previous in-memory state is retained.
  AdapterWriteRejected = 'AdapterWriteRejected',
}

/**
 * RevocationStage names the phase the revocation had reached when it settled.
 */
export enum RevocationStage {
  // Existence check against the in-memory model.
  Lookup = 'lookup',
  // Writing the removal through the configured adapter.
  Persist = 'persist',
  // Applying the removal to the in-memory model and invalidating decisions.
  Apply = 'apply',
}

/**
 * RevocationDiagnostic is the reviewable record of one named-policy revocation.
 * It deliberately carries no rule fields or user data: only the named policy
 * type, the reached stage and the result category are reported.
 */
export interface RevocationDiagnostic {
  // The named policy type, e.g. "p", "p2".
  ptype: string;
  stage: RevocationStage;
  category: RevocationResultCategory;
  // True only when the revocation is fully applied and the next decision
  // cannot be served from a pre-revocation allow cache.
  applied: boolean;
}
