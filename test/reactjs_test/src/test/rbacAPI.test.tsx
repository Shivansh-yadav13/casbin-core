import { Model, MemoryAdapter, newEnforcer } from '../../../../src';
import {getEnforcerWithPath} from "../../../utils";

test('test getRolesForUser', async () => {
    const model = new Model(`
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
    `);
    const adapter = new MemoryAdapter(`
    p, alice, data1, read
    p, bob, data2, write
    p, data1_admin, data1, read
    p, data1_admin, data1, write
    p, data2_admin, data2, read
    p, data2_admin, data2, write

    g, alice, admin
    g, admin, data1_admin
    g, admin, data2_admin
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.getRolesForUser('alice')).toEqual(['admin']);
});

test('test getRolesForUser with domain', async () => {
    const model = new Model(`
    [request_definition]
    r = sub, dom, obj, act

    [policy_definition]
    p = sub, dom, obj, act

    [role_definition]
    g = _, _, _

    [policy_effect]
    e = some(where (p.eft == allow))

    [matchers]
    m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
    `);
    const adapter = new MemoryAdapter(`
    p, role:reader, domain1, data1, read
    p, role:writer, domain1, data1, write

    g, role:global_admin, role:reader, domain1
    g, role:global_admin, role:writer, domain1

    g, alice, role:global_admin, domain1
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.getRolesForUser('alice', 'domain1')).toEqual(['role:global_admin']);
});

test('test add/deleteRoleForUSer', async () => {
    const model = new Model(`
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
    `);
    const adapter = new MemoryAdapter(`
    p, alice, data1, read
    p, bob, data2, write
    p, data1_admin, data1, read
    p, data1_admin, data1, write
    p, data2_admin, data2, read
    p, data2_admin, data2, write

    g, alice, admin
    g, admin, data1_admin
    g, admin, data2_admin
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.getRolesForUser('bob')).toEqual([]);
    expect(await e.addRoleForUser('bob', 'data1_admin')).toEqual(true);
    expect(await e.hasRoleForUser('bob', 'data1_admin')).toEqual(true);
    expect(await e.getUsersForRole('data1_admin')).toEqual(['admin', 'bob']);
    expect(await e.deleteRoleForUser('bob', 'data1_admin')).toEqual(true);
    expect(await e.hasRoleForUser('bob', 'role:global_admin')).toEqual(false);
    expect(await e.getUsersForRole('data1_admin')).toEqual(['admin']);
});

test('test add/deleteRoleForUSer with domain', async () => {
    const model = new Model(`
    [request_definition]
    r = sub, dom, obj, act

    [policy_definition]
    p = sub, dom, obj, act

    [role_definition]
    g = _, _, _

    [policy_effect]
    e = some(where (p.eft == allow))

    [matchers]
    m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
    `);
    const adapter = new MemoryAdapter(`
    p, role:reader, domain1, data1, read
    p, role:writer, domain1, data1, write

    g, role:global_admin, role:reader, domain1
    g, role:global_admin, role:writer, domain1

    g, alice, role:global_admin, domain1
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.getRolesForUser('bob', 'domain1')).toEqual([]);
    expect(await e.addRoleForUser('bob', 'role:global_admin', 'domain1')).toEqual(true);
    expect(await e.hasRoleForUser('bob', 'role:global_admin', 'domain1')).toEqual(true);
    expect(await e.getUsersForRole('role:global_admin', 'domain1')).toEqual(['alice', 'bob']);
    expect(await e.deleteRoleForUser('bob', 'role:global_admin', 'domain1')).toEqual(true);
    expect(await e.hasRoleForUser('bob', 'role:global_admin', 'domain1')).toEqual(false);
    expect(await e.getUsersForRole('role:global_admin', 'domain1')).toEqual(['alice']);
});

test('test getImplicitRolesForUser', async () => {
    const model = new Model(`
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
    `);
    const adapter = new MemoryAdapter(`
    p, alice, data1, read
    p, bob, data2, write
    p, data1_admin, data1, read
    p, data1_admin, data1, write
    p, data2_admin, data2, read
    p, data2_admin, data2, write

    g, alice, admin
    g, admin, data1_admin
    g, admin, data2_admin
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.getImplicitRolesForUser('bob')).toEqual([]);
    expect(await e.getImplicitRolesForUser('alice')).toEqual(['admin', 'data1_admin', 'data2_admin']);
});

test('test getImplicitRolesForUser with domain', async () => {
    const model = new Model(`
    [request_definition]
    r = sub, dom, obj, act

    [policy_definition]
    p = sub, dom, obj, act

    [role_definition]
    g = _, _, _

    [policy_effect]
    e = some(where (p.eft == allow))

    [matchers]
    m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
    `);
    const adapter = new MemoryAdapter(`
    p, role:reader, domain1, data1, read
    p, role:writer, domain1, data1, write

    g, role:global_admin, role:reader, domain1
    g, role:global_admin, role:writer, domain1

    g, alice, role:global_admin, domain1
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.getImplicitRolesForUser('alice', 'domain1')).toEqual(['role:global_admin', 'role:reader', 'role:writer']);
});

test('test getImplicitPermissionsForUser', async () => {
    const model = new Model(`
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
    `);
    const adapter = new MemoryAdapter(`
    p, alice, data1, read
    p, bob, data2, write
    p, data1_admin, data1, read
    p, data1_admin, data1, write
    p, data2_admin, data2, read
    p, data2_admin, data2, write

    g, alice, admin
    g, admin, data1_admin
    g, admin, data2_admin
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.hasPermissionForUser('bob', 'data2', 'write')).toEqual(true);
    expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
    expect(await e.hasPermissionForUser('alice', 'data1', 'read')).toEqual(true);
    expect(await e.hasPermissionForUser('data1_admin', 'data1', 'read')).toEqual(true);
    expect(await e.hasPermissionForUser('data1_admin', 'data1', 'write')).toEqual(true);
    expect(await e.hasPermissionForUser('data2_admin', 'data2', 'read')).toEqual(true);
    expect(await e.hasPermissionForUser('data2_admin', 'data2', 'write')).toEqual(true);
    expect(await e.getImplicitPermissionsForUser('alice')).toEqual([
        ['alice', 'data1', 'read'],
        ['data1_admin', 'data1', 'read'],
        ['data1_admin', 'data1', 'write'],
        ['data2_admin', 'data2', 'read'],
        ['data2_admin', 'data2', 'write'],
    ]);
});

test('test deleteRolesForUser', async () => {
    const model = new Model(`
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
    `);
    const adapter = new MemoryAdapter(`
    p, alice, data1, read
    p, bob, data2, write
    p, data1_admin, data1, read
    p, data1_admin, data1, write
    p, data2_admin, data2, read
    p, data2_admin, data2, write

    g, alice, admin
    g, admin, data1_admin
    g, admin, data2_admin
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.hasPermissionForUser('bob', 'data2', 'write')).toEqual(true);
    expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
    expect(await e.getImplicitPermissionsForUser('alice')).toEqual([
        ['alice', 'data1', 'read'],
        ['data1_admin', 'data1', 'read'],
        ['data1_admin', 'data1', 'write'],
        ['data2_admin', 'data2', 'read'],
        ['data2_admin', 'data2', 'write'],
    ]);
    expect(await e.deleteRolesForUser('alice')).toEqual(true);
    expect(await e.hasPermissionForUser('alice', 'data1', 'read')).toEqual(true);
    expect(await e.getImplicitPermissionsForUser('alice')).toEqual([['alice', 'data1', 'read']]);
    expect(await e.hasPermissionForUser('bob', 'data2', 'write')).toEqual(true);
    expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
    expect(await e.deleteRolesForUser('bob')).toEqual(false);
    expect(await e.hasPermissionForUser('alice', 'data1', 'read')).toEqual(true);
    expect(await e.getImplicitPermissionsForUser('alice')).toEqual([['alice', 'data1', 'read']]);
    expect(await e.hasPermissionForUser('bob', 'data2', 'write')).toEqual(true);
    expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
});

test('test deleteRolesForUser with domain', async () => {
    const model = new Model(`
    [request_definition]
    r = sub, dom, obj, act

    [policy_definition]
    p = sub, dom, obj, act

    [role_definition]
    g = _, _, _

    [policy_effect]
    e = some(where (p.eft == allow))

    [matchers]
    m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
    `);
    const adapter = new MemoryAdapter(`
    p, admin, domain1, data1, read
    p, admin, domain1, data1, write
    p, admin, domain2, data2, read
    p, admin, domain2, data2, write

    g, alice, admin, domain1
    g, bob, admin, domain2
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.getImplicitRolesForUser('alice', 'domain1')).toEqual(['admin']);
    expect(await e.getImplicitPermissionsForUser('alice', 'domain1')).toEqual([
        ['admin', 'domain1', 'data1', 'read'],
        ['admin', 'domain1', 'data1', 'write'],
    ]);
    expect(await e.getImplicitPermissionsForUser('bob', 'domain2')).toEqual([
        ['admin', 'domain2', 'data2', 'read'],
        ['admin', 'domain2', 'data2', 'write'],
    ]);
    expect(await e.deleteRolesForUser('alice', 'domain1')).toEqual(true);
    expect(await e.getImplicitRolesForUser('alice', 'domain1')).toEqual([]);
    expect(await e.getImplicitPermissionsForUser('alice', 'domain2')).toEqual([]);
    expect(await e.getImplicitPermissionsForUser('bob', 'domain2')).toEqual([
        ['admin', 'domain2', 'data2', 'read'],
        ['admin', 'domain2', 'data2', 'write'],
    ]);
    expect(await e.deleteRolesForUser('bob', 'domain1')).toEqual(false);
    expect(await e.getImplicitPermissionsForUser('alice', 'domain2')).toEqual([]);
    expect(await e.getImplicitPermissionsForUser('bob', 'domain1')).toEqual([]);
});

test('test deleteRole', async () => {
    const model = new Model(`
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
    `);
    const adapter = new MemoryAdapter(`
    p, alice, data1, read
    p, bob, data2, write
    p, data1_admin, data1, read
    p, data1_admin, data1, write
    p, data2_admin, data2, read
    p, data2_admin, data2, write

    g, alice, admin
    g, admin, data1_admin
    g, admin, data2_admin
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
    expect(await e.getImplicitPermissionsForUser('alice')).toEqual([
        ['alice', 'data1', 'read'],
        ['data1_admin', 'data1', 'read'],
        ['data1_admin', 'data1', 'write'],
        ['data2_admin', 'data2', 'read'],
        ['data2_admin', 'data2', 'write'],
    ]);
    expect(await e.deleteRole('data1_admin')).toEqual(true);
    expect(await e.getImplicitPermissionsForUser('alice')).toEqual([
        ['alice', 'data1', 'read'],
        ['data2_admin', 'data2', 'read'],
        ['data2_admin', 'data2', 'write'],
    ]);
    await e.deleteRole('data2_admin');
    expect(await e.getImplicitPermissionsForUser('alice')).toEqual([['alice', 'data1', 'read']]);
});

test('test deleteUser', async () => {
    const model = new Model(`
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
    `);
    const adapter = new MemoryAdapter(`
    p, alice, data1, read
    p, bob, data2, write
    p, data1_admin, data1, read
    p, data1_admin, data1, write
    p, data2_admin, data2, read
    p, data2_admin, data2, write

    g, alice, admin
    g, admin, data1_admin
    g, admin, data2_admin
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
    expect(await e.getImplicitPermissionsForUser('alice')).toEqual([
        ['alice', 'data1', 'read'],
        ['data1_admin', 'data1', 'read'],
        ['data1_admin', 'data1', 'write'],
        ['data2_admin', 'data2', 'read'],
        ['data2_admin', 'data2', 'write'],
    ]);
    await e.deleteUser('alice');
    expect(await e.getImplicitPermissionsForUser('alice')).toEqual([]);
    expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
    await e.deleteRole('bob');
    expect(await e.getImplicitPermissionsForUser('alice')).toEqual([]);
    expect(await e.getImplicitPermissionsForUser('bob')).toEqual([]);
});

test('test getImplicitUsersForPermission', async () => {
    const model = new Model(`
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
    `);
    const adapter = new MemoryAdapter(`
    p, alice, data1, read
    p, bob, data2, write
    p, data1_admin, data1, read
    p, data1_admin, data1, write
    p, data2_admin, data2, read
    p, data2_admin, data2, write

    g, alice, admin
    g, admin, data1_admin
    g, admin, data2_admin
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.getImplicitUsersForPermission('data1', 'read')).toEqual(['alice']);
    expect(await e.getImplicitUsersForPermission('data1', 'write')).toEqual(['alice']);
    expect(await e.getImplicitUsersForPermission('data2', 'read')).toEqual(['alice']);
    expect(await e.getImplicitUsersForPermission('data2', 'write')).toEqual(['alice', 'bob']);

    e.clearPolicy();

    await e.addPolicy('admin', 'data1', 'read');
    await e.addPolicy('bob', 'data1', 'read');
    await e.addGroupingPolicy('alice', 'admin');

    expect(await e.getImplicitUsersForPermission('data1', 'read')).toEqual(['bob', 'alice']);
});

test('test getImplicitUsersForRole', async () => {
    const model = new Model(`
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
    `);
    const adapter = new MemoryAdapter(`
    p, alice, data1, read
    p, bob, data2, write
    p, data1_admin, data1, read
    p, data1_admin, data1, write
    p, data2_admin, data2, read
    p, data2_admin, data2, write

    g, alice, admin
    g, admin, data1_admin
    g, admin, data2_admin
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.getImplicitUsersForRole('admin')).toEqual(['alice']);
    expect(await e.getImplicitUsersForRole('data1_admin')).toEqual(['admin', 'alice']);
});

test('test getPermissionsForUserInDomain', async () => {
    const model = new Model(`
    [request_definition]
    r = sub, dom, obj, act

    [policy_definition]
    p = sub, dom, obj, act

    [role_definition]
    g = _, _, _

    [policy_effect]
    e = some(where (p.eft == allow))

    [matchers]
    m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
    `);
    const adapter = new MemoryAdapter(`
    p, admin, domain1, data1, read
    p, admin, domain1, data1, write
    p, admin, domain2, data2, read
    p, admin, domain2, data2, write

    g, alice, admin, domain1
    g, bob, admin, domain2
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.getPermissionsForUserInDomain('alice', 'domain1')).toEqual([
        ['admin', 'domain1', 'data1', 'read'],
        ['admin', 'domain1', 'data1', 'write'],
    ]);
    expect(await e.getPermissionsForUserInDomain('bob', 'domain2')).toEqual([
        ['admin', 'domain2', 'data2', 'read'],
        ['admin', 'domain2', 'data2', 'write'],
    ]);
});

test('test add/deleteRoleForUserInDomain', async () => {
    const model = new Model(`
    [request_definition]
    r = sub, dom, obj, act

    [policy_definition]
    p = sub, dom, obj, act

    [role_definition]
    g = _, _, _

    [policy_effect]
    e = some(where (p.eft == allow))

    [matchers]
    m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
    `);
    const adapter = new MemoryAdapter(`
    p, role:reader, domain1, data1, read
    p, role:writer, domain1, data1, write

    g, role:global_admin, role:reader, domain1
    g, role:global_admin, role:writer, domain1

    g, alice, role:global_admin, domain1
    `);
    const e = await newEnforcer(model, adapter);
    expect(await e.addRoleForUserInDomain('bob', 'role:global_admin', 'domain1')).toEqual(true);
    expect(await e.hasRoleForUser('bob', 'role:global_admin', 'domain1')).toEqual(true);
    expect(await e.getUsersForRole('role:global_admin', 'domain1')).toEqual(['alice', 'bob']);
    expect(await e.deleteRoleForUserInDomain('bob', 'role:global_admin', 'domain1')).toEqual(true);
    expect(await e.hasRoleForUser('bob', 'role:global_admin', 'domain1')).toEqual(false);
    expect(await e.getUsersForRole('role:global_admin', 'domain1')).toEqual(['alice']);
});