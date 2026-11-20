import { chromium } from "playwright";

export function launchAuthorBrowser() {
  // The macOS shell's separate GPU helper can fail to locate its ICU bundle.
  // Keep the bundled shell's input routing and avoid launching that helper.
  if (process.platform !== "darwin") return chromium.launch({ headless: true });
  return chromium.launch({
    headless: true, args: ["--in-process-gpu"],
    env: { ...process.env, ...(process.env.TMPDIR ? { MAC_CHROMIUM_TMPDIR: process.env.MAC_CHROMIUM_TMPDIR || process.env.TMPDIR } : {}) },
  });
}
