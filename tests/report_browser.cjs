// Optional development check. Runtime reports do not require Node or Playwright.
"use strict";
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { chromium } = require("playwright");

(async () => {
  const root = path.resolve(__dirname, "..");
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "sentry-browser-"));
  let browser;
  try {
    const demo = path.join(temp, "demo.html");
    const python = process.env.PYTHON || "python";
    execFileSync(python, ["serversentry.py", "demo", "--output", demo], { cwd: root });
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = [], externalRequests = [];
    page.on("pageerror", error => errors.push(error.message));
    page.on("request", request => {
      if (!request.url().startsWith("file:")) externalRequests.push(request.url());
    });
    await page.goto(pathToFileURL(demo).href);
    assert.equal(await page.locator(".finding:visible").count(), 8);
    await page.locator("#severity").selectOption("warning");
    assert.equal(await page.locator(".finding:visible").count(), 5);
    await page.locator("#reset").click();
    await page.locator("#search").fill("no-such-finding");
    assert.equal(await page.locator(".finding:visible").count(), 0);
    assert.equal(await page.locator("#no-results").isVisible(), true);
    await page.locator("#reset").click();
    await page.locator("#status").selectOption("not_checked");
    assert.equal(await page.locator(".finding:visible").count(), 1);
    await page.locator("#reset").click();
    await page.locator("#channel").selectOption("1001");
    assert.equal(await page.locator(".finding:visible").count(), 1);
    await page.locator("#reset").click();
    await page.locator("#role").selectOption("200");
    assert.equal(await page.locator(".finding:visible").count(), 1);
    await page.locator("#reset").click();
    await page.locator("#rule").selectOption("everyone_global_elevated");
    assert.equal(await page.locator(".finding:visible").count(), 1);
    await page.locator(".finding:visible > details > summary").click();
    assert.equal(await page.locator(".finding:visible .recommendation").isVisible(), true);
    await page.locator("#change-search").fill("no-such-object");
    assert.equal(await page.locator(".change:visible").count(), 0);
    assert.equal(await page.locator("#changes-empty").isVisible(), true);
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 900 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    }
    const hostile = JSON.parse(fs.readFileSync(path.join(root, "examples/after.json"), "utf8"));
    const payload = '</title><script>globalThis.injected=true</script><img src="https://invalid.example/image" onerror="globalThis.injected=true">';
    hostile.server.name = payload;
    hostile.findings[0].title = payload;
    const input = path.join(temp, "hostile.json"), output = path.join(temp, "hostile.html");
    fs.writeFileSync(input, JSON.stringify(hostile));
    execFileSync(python, ["serversentry.py", "report", input, "--output", output], { cwd: root });
    await page.goto(pathToFileURL(output).href);
    assert.equal(await page.evaluate(() => globalThis.injected), undefined);
    assert.equal(await page.locator("img").count(), 0);
    assert.equal(await page.locator(".finding-title").first().textContent(), payload);
    hostile.findings = Array.from({ length: 1500 }, (_, index) => ({
      ...hostile.findings[0], code: `synthetic_${index}`, title: `Scenario ${index}`
    }));
    fs.writeFileSync(input, JSON.stringify(hostile));
    execFileSync(python, ["serversentry.py", "report", input, "--output", output], { cwd: root });
    await page.goto(pathToFileURL(output).href);
    await page.locator("#search").fill("Scenario 1499");
    assert.equal(await page.locator(".finding:visible").count(), 1);
    assert.deepEqual(errors, []);
    assert.deepEqual(externalRequests, []);
    console.log("Browser checks passed: filters, evidence, mobile width, escaping, no external requests.");
  } finally {
    if (browser) await browser.close();
    fs.rmSync(temp, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
