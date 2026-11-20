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

import {
  CachedEnforcer,
  Enforcer,
  Model,
  RevocationResultCategory,
  RevocationStage,
  newCachedEnforcer,
  newEnforcer,
  newModel,
} from '../src';
import { Adapter } from '../src/persist/adapter';

const BASIC_MODEL = `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`;

const MULTI_PTYPE_MODEL = `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
p2 = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`;

// WritableAdapter is an in-memory Adapter double: removePolicy really deletes
// the rule, and every storage interaction is observable through the jest mocks.
class WritableAdapter implements Adapter {
  public rules: string[][] = [];
  public loadPolicy = jest.fn(
    async (): Promise<void> => {
      /* no-op: rules are seeded through the management API */
    }
  );
  public savePolicy = jest.fn(async (): Promise<boolean> => true);
  public addPolicy = jest.fn(
    async (_sec: string, _ptype: string, rule: string[]): Promise<void> => {
      this.rules.push([...rule]);
    }
  );
  public removePolicy = jest.fn(
    async (_sec: string, _ptype: string, rule: string[]): Promise<void> => {
      this.rules = this.rules.filter((r) => r.join(',') !== rule.join(','));
    }
  );
  public removeFilteredPolicy = jest.fn(
    async (): Promise<void> => {
      /* no-op */
    }
  );
}

// ReadOnlyAdapter refuses every write, modelling storage that did not land.
class ReadOnlyAdapter implements Adapter {
  public loadPolicy = jest.fn(
    async (): Promise<void> => {
      /* no-op: the trusted state is seeded in memory */
    }
  );
  public savePolicy = jest.fn(
    async (): Promise<boolean> => {
      throw new Error('storage is read-only');
    }
  );
  public addPolicy = jest.fn(
    async (): Promise<void> => {
      throw new Error('storage is read-only');
    }
  );
  public removePolicy = jest.fn(
    async (): Promise<void> => {
      throw new Error('storage is read-only');
    }
  );
  public removeFilteredPolicy = jest.fn(
    async (): Promise<void> => {
      throw new Error('storage is read-only');
    }
  );
}

async function newEnforcerWithModel(modelText: string, adapter: Adapter): Promise<Enforcer> {
  const model: Model = newModel(modelText);
  return newEnforcer(model, adapter);
}

describe('revokeNamedPolicyWithDiagnostic on the management entry', () => {
  let e: Enforcer;
  let adapter: WritableAdapter;

  const targetRule = ['alice', 'data1', 'read'];
  const controlRule = ['bob', 'data2', 'write'];

  beforeEach(async () => {
    adapter = new WritableAdapter();
    e = await newEnforcerWithModel(BASIC_MODEL, adapter);
    e.enableAutoSave(true);
    // Rules enter through the public management API so the in-memory model is
    // the trusted starting state.
    await e.addPolicy(...targetRule);
    await e.addPolicy(...controlRule);
  });

  test('writable adapter: write, read-back and re-judgement happen in order and the rule is revoked', async () => {
    // Pre-warm the decision for the target rule and the control rule.
    await expect(e.enforce('alice', 'data1', 'read')).resolves.toBe(true);
    await expect(e.enforce('bob', 'data2', 'write')).resolves.toBe(true);

    // Observe the public read-back entry so its position relative to the
    // adapter write can be compared through invocation call ordering.
    const readBackSpy = jest.spyOn(e, 'hasNamedPolicy');

    const diagnostic = await e.revokeNamedPolicyWithDiagnostic('p', targetRule);

    expect(diagnostic).toEqual({
      ptype: 'p',
      stage: RevocationStage.Apply,
      category: RevocationResultCategory.Revoked,
      applied: true,
    });
    // The diagnostic must not carry rule fields or user data.
    expect(Object.keys(diagnostic).sort()).toEqual(['applied', 'category', 'ptype', 'stage']);

    // Exactly one write, targeting the rule under revocation on this adapter only.
    expect(adapter.removePolicy).toHaveBeenCalledTimes(1);
    expect(adapter.removePolicy).toHaveBeenCalledWith('p', 'p', targetRule);
    expect(adapter.addPolicy).toHaveBeenCalledTimes(2);
    expect(adapter.removeFilteredPolicy).not.toHaveBeenCalled();
    expect(adapter.savePolicy).not.toHaveBeenCalled();

    // Read-back through the public management entry reflects the new policy.
    expect(await e.hasNamedPolicy('p', ...targetRule)).toBe(false);
    expect(await e.hasPolicy(...targetRule)).toBe(false);
    expect(await e.getNamedPolicy('p')).toEqual([controlRule]);

    // Event ordering: the adapter write precedes the public read-back, which
    // precedes the re-judgement below.
    const writeOrder = adapter.removePolicy.mock.invocationCallOrder[0];
    const readBackOrder = readBackSpy.mock.invocationCallOrder[0];
    expect(readBackOrder).toBeGreaterThan(writeOrder);

    // The next authorization is judged against the new policy.
    await expect(e.enforce('alice', 'data1', 'read')).resolves.toBe(false);
    // Unrelated named rules keep their existing semantics.
    await expect(e.enforce('bob', 'data2', 'write')).resolves.toBe(true);
    expect(await e.hasPolicy(...controlRule)).toBe(true);

    // The storage side also dropped the rule and kept the control rule.
    expect(adapter.rules.map((r) => r.join(','))).not.toContain(targetRule.join(','));
    expect(adapter.rules.map((r) => r.join(','))).toContain(controlRule.join(','));

    readBackSpy.mockRestore();
  });

  test('read-only adapter: the rejection is diagnosed and the previous authorization is preserved', async () => {
    const readOnly = new ReadOnlyAdapter();
    const rejected = await newEnforcerWithModel(BASIC_MODEL, readOnly);
    rejected.enableAutoSave(true);
    // The adapter refuses writes, so seed the trusted state directly in memory.
    await rejected.selfAddPolicy('p', 'p', targetRule);
    await rejected.selfAddPolicy('p', 'p', controlRule);

    // Pre-warm the decision before the failed revocation.
    await expect(rejected.enforce('alice', 'data1', 'read')).resolves.toBe(true);

    const diagnostic = await rejected.revokeNamedPolicyWithDiagnostic('p', targetRule);

    expect(diagnostic).toEqual({
      ptype: 'p',
      stage: RevocationStage.Persist,
      category: RevocationResultCategory.AdapterWriteRejected,
      applied: false,
    });

    // A write was attempted exactly once, against this same instance...
    expect(readOnly.removePolicy).toHaveBeenCalledTimes(1);
    expect(readOnly.removePolicy).toHaveBeenCalledWith('p', 'p', targetRule);
    // ...and no other write-shaped adapter method was used.
    expect(readOnly.removeFilteredPolicy).not.toHaveBeenCalled();
    expect(readOnly.savePolicy).not.toHaveBeenCalled();

    // The last trusted state is retained: the rule still authorizes, and the
    // "not found" category must not masquerade as a successful update.
    expect(await rejected.hasPolicy(...targetRule)).toBe(true);
    expect(await rejected.getNamedPolicy('p')).toEqual([targetRule, controlRule]);
    await expect(rejected.enforce('alice', 'data1', 'read')).resolves.toBe(true);
    await expect(rejected.enforce('bob', 'data2', 'write')).resolves.toBe(true);

    // The separate writable adapter instance received no removal at all,
    // confirming a revocation never fans out to another adapter.
    expect(adapter.removePolicy).not.toHaveBeenCalled();
  });

  test('a missing rule is reported as PolicyNotFound without any adapter write or state change', async () => {
    const missing = ['nobody', 'data3', 'read'];

    const diagnostic = await e.revokeNamedPolicyWithDiagnostic('p', missing);

    expect(diagnostic).toEqual({
      ptype: 'p',
      stage: RevocationStage.Lookup,
      category: RevocationResultCategory.PolicyNotFound,
      applied: false,
    });
    expect(adapter.removePolicy).not.toHaveBeenCalled();
    expect(adapter.removeFilteredPolicy).not.toHaveBeenCalled();

    // An absent rule must not be reported as a successful update: both existing
    // rules and their decisions remain untouched.
    expect(await e.hasPolicy(...targetRule)).toBe(true);
    expect(await e.hasPolicy(...controlRule)).toBe(true);
    await expect(e.enforce('alice', 'data1', 'read')).resolves.toBe(true);
    await expect(e.enforce('bob', 'data2', 'write')).resolves.toBe(true);
  });

  test('identical fields under different named policies resolve to the correct ptype', async () => {
    const multi = await newEnforcerWithModel(MULTI_PTYPE_MODEL, new WritableAdapter());
    multi.enableAutoSave(true);
    const sharedRule = ['carol', 'data9', 'read'];
    await multi.addNamedPolicy('p', ...sharedRule);
    await multi.addNamedPolicy('p2', ...sharedRule);

    const diagnostic = await multi.revokeNamedPolicyWithDiagnostic('p2', sharedRule);

    expect(diagnostic.ptype).toBe('p2');
    expect(diagnostic.category).toBe(RevocationResultCategory.Revoked);

    // Only p2 lost the rule; p keeps an identical-looking rule untouched.
    expect(await multi.hasNamedPolicy('p2', ...sharedRule)).toBe(false);
    expect(await multi.hasNamedPolicy('p', ...sharedRule)).toBe(true);
    expect(await multi.getNamedPolicy('p2')).toEqual([]);
    expect(await multi.getNamedPolicy('p')).toEqual([sharedRule]);

    // Revoking the same rule again under p2 is a lookup miss, not a success.
    const again = await multi.revokeNamedPolicyWithDiagnostic('p2', sharedRule);
    expect(again.category).toBe(RevocationResultCategory.PolicyNotFound);
    expect(again.stage).toBe(RevocationStage.Lookup);
  });
});

describe('revokeNamedPolicyWithDiagnostic and the decision cache', () => {
  let e: CachedEnforcer;
  let adapter: WritableAdapter;

  const targetRule = ['alice', 'data1', 'read'];
  const controlRule = ['bob', 'data2', 'write'];

  beforeEach(async () => {
    adapter = new WritableAdapter();
    const model: Model = newModel(BASIC_MODEL);
    e = await newCachedEnforcer(model, adapter);
    e.enableAutoSave(true);
    await e.addPolicy(...targetRule);
    await e.addPolicy(...controlRule);
  });

  test('a successful revocation invalidates the cache and the next allow is re-judged', async () => {
    // Count how often the real (non-cached) enforcement runs.
    const superEnforce = jest.spyOn(Enforcer.prototype, 'enforce');

    // Pre-warm both decisions so they are served from the cache afterwards.
    await expect(e.enforce('alice', 'data1', 'read')).resolves.toBe(true);
    await expect(e.enforce('bob', 'data2', 'write')).resolves.toBe(true);
    const superCallsAfterWarmup = superEnforce.mock.calls.length;

    // Cache hits must not reach the real enforcement.
    await e.enforce('alice', 'data1', 'read');
    await e.enforce('bob', 'data2', 'write');
    expect(superEnforce.mock.calls.length).toBe(superCallsAfterWarmup);

    const diagnostic = await e.revokeNamedPolicyWithDiagnostic('p', targetRule);
    expect(diagnostic.category).toBe(RevocationResultCategory.Revoked);

    // Cache invalidation forces a fresh judgement rather than the stale allow.
    await expect(e.enforce('alice', 'data1', 'read')).resolves.toBe(false);
    expect(superEnforce.mock.calls.length).toBe(superCallsAfterWarmup + 1);

    // The re-judged denial is itself cached (no further super call on repeat).
    await e.enforce('alice', 'data1', 'read');
    expect(superEnforce.mock.calls.length).toBe(superCallsAfterWarmup + 1);

    // The control rule keeps being allowed after invalidation.
    await expect(e.enforce('bob', 'data2', 'write')).resolves.toBe(true);
    superEnforce.mockRestore();
  });

  test('a rejected write leaves the previous allow cache in force and creates no new allow entry', async () => {
    const readOnly = new ReadOnlyAdapter();
    const model: Model = newModel(BASIC_MODEL);
    const cached = await newCachedEnforcer(model, readOnly);
    cached.enableAutoSave(true);
    await cached.selfAddPolicy('p', 'p', targetRule);
    await cached.selfAddPolicy('p', 'p', controlRule);

    const superEnforce = jest.spyOn(Enforcer.prototype, 'enforce');

    // Pre-warm the target decision.
    await expect(cached.enforce('alice', 'data1', 'read')).resolves.toBe(true);
    const superCallsAfterWarmup = superEnforce.mock.calls.length;

    const diagnostic = await cached.revokeNamedPolicyWithDiagnostic('p', targetRule);
    expect(diagnostic.category).toBe(RevocationResultCategory.AdapterWriteRejected);

    // The pre-existing allow cache is still reusable, so no re-judgement runs
    // and no fresh allow cache entry is written.
    await expect(cached.enforce('alice', 'data1', 'read')).resolves.toBe(true);
    expect(superEnforce.mock.calls.length).toBe(superCallsAfterWarmup);

    // The in-memory trusted state backs the cached decision.
    expect(await cached.hasPolicy(...targetRule)).toBe(true);
    superEnforce.mockRestore();
  });

  test('a missing rule leaves the cache and all prior decisions untouched', async () => {
    const superEnforce = jest.spyOn(Enforcer.prototype, 'enforce');
    await e.enforce('alice', 'data1', 'read');
    const superCallsAfterWarmup = superEnforce.mock.calls.length;

    const diagnostic = await e.revokeNamedPolicyWithDiagnostic('p', ['nobody', 'data3', 'read']);
    expect(diagnostic.category).toBe(RevocationResultCategory.PolicyNotFound);
    expect(adapter.removePolicy).not.toHaveBeenCalled();

    // Still served from the pre-warmed cache: no re-judgement, decision intact.
    await expect(e.enforce('alice', 'data1', 'read')).resolves.toBe(true);
    expect(superEnforce.mock.calls.length).toBe(superCallsAfterWarmup);
    superEnforce.mockRestore();
  });
});
