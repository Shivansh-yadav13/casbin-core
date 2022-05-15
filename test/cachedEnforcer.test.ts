// Copyright 2020 The Casbin Authors. All Rights Reserved.
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

import { Enforcer, MemoryAdapter, Model, newCachedEnforcer } from '../src';
import { path2Content } from './utils';

async function testEnforce(e: Enforcer, sub: string, obj: string, act: string, res: boolean): Promise<void> {
  await expect(e.enforce(sub, obj, act)).resolves.toBe(res);
}

test('TestRBACModel', async () => {
  const m = new Model(path2Content('examples/rbac_model.conf'));
  const a = new MemoryAdapter(path2Content('examples/rbac_policy.csv'));
  const e = await newCachedEnforcer(m, a);

  await testEnforce(e, 'alice', 'data1', 'read', true);
});
