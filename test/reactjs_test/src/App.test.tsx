import { Model, MemoryAdapter, newEnforcer } from '../../../src';

test('enforces correctly', async () => {
  const model = `
  [request_definition]
  r = sub, obj, act

  [policy_definition]
  p = sub, obj, act

  [role_definition]
  g = _, _

  [policy_effect]
  e = some(where (p.eft == allow))

  [matchers]
  m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
  `
  const m = new Model(model);

  const e = await newEnforcer(m, new MemoryAdapter(`
  p, alice, data1, read
  p, bob, data2, write
  `));
  expect(await e.enforce('bob', 'data2', 'write')).toBe(true);
  expect(await e.enforce('alice', 'data1', 'read')).toBe(true);
  expect(await e.enforce('alice', 'data2', 'write')).toBe(false);
});

