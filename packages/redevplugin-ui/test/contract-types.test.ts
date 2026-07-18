import type {
  PluginCapabilityContractPin,
  PluginRecord,
  PluginSettingsPatchRequest,
} from "../src/platform.js";

type IsUnknown<T> = unknown extends T ? ([keyof T] extends [never] ? true : false) : false;

const patchIsNotUnknown: IsUnknown<PluginSettingsPatchRequest> = false;
const pinIsNotUnknown: IsUnknown<PluginCapabilityContractPin> = false;
const manifestIsNotUnknown: IsUnknown<PluginRecord["manifest"]> = false;
void patchIsNotUnknown;
void pinIsNotUnknown;
void manifestIsNotUnknown;

const setPatch: PluginSettingsPatchRequest = {
  scope: "user",
  expected_values_revision: 1,
  set: { theme: "dark" },
};
const removePatch: PluginSettingsPatchRequest = {
  scope: "environment",
  expected_values_revision: 1,
  remove: ["obsolete"],
};
void setPatch;
void removePatch;

// @ts-expect-error A settings patch must contain set or remove.
const missingOperation: PluginSettingsPatchRequest = { scope: "user", expected_values_revision: 1 };
// @ts-expect-error remove must contain at least one key.
const emptyRemove: PluginSettingsPatchRequest = { scope: "user", expected_values_revision: 1, remove: [] };
// @ts-expect-error Settings scope is a closed user/environment value.
const invalidScope: PluginSettingsPatchRequest = { scope: "global", expected_values_revision: 1, set: { theme: "dark" } };
// @ts-expect-error Settings patches must explicitly select their resource scope.
const missingScope: PluginSettingsPatchRequest = { expected_values_revision: 1, set: { theme: "dark" } };
// @ts-expect-error Capability pins require their complete immutable identity.
const incompletePin: PluginCapabilityContractPin = { publisher_id: "example" };
void missingOperation;
void emptyRemove;
void invalidScope;
void missingScope;
void incompletePin;
