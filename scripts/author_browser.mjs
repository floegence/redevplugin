import { chromium } from "playwright";

export function launchAuthorBrowser() {
  // The macOS headless shell's GPU helper cannot reliably resolve its ICU bundle.
  // Use Playwright's matching full Chromium in headless mode on that platform.
  if (process.platform !== "darwin") return chromium.launch({ headless: true });
  return chromium.launch({
    channel: "chromium", headless: true,
    env: { ...process.env, ...(process.env.TMPDIR ? { MAC_CHROMIUM_TMPDIR: process.env.MAC_CHROMIUM_TMPDIR || process.env.TMPDIR } : {}) },
  });
}
