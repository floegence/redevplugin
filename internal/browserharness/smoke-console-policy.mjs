const expectedSecurityProbeFragments = [
  "violates the following Content Security Policy directive",
  "Refused to connect because it violates the document's Content Security Policy",
  "Failed to load resource: the server responded with a status of 409",
];

export function isExpectedSandboxConsoleLine(entry) {
  if (entry === "warning: Unrecognized feature: 'bluetooth'.") return true;
  return expectedSecurityProbeFragments.some((fragment) => entry.includes(fragment));
}
