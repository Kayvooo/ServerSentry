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
    const visible = () => page.locator(".finding:visible").count();
    assert.equal(await visible(), 11);
    await page.locator('#severity-filter button[data-value="warning"]').click();
    assert.equal(await visible(), 7);
    assert.equal(await page.locator('#severity-filter button[data-value="warning"]').getAttribute("aria-pressed"), "true");
    await page.locator("#reset").click();
    assert.equal(await visible(), 11);
    await page.locator("#search").fill("no-such-finding");
    assert.equal(await visible(), 0);
    assert.equal(await page.locator("#no-results").isVisible(), true);
    await page.locator("#reset").click();
    await page.locator(".more > summary").click();
    await page.locator("#status").selectOption("not_checked");
    assert.equal(await visible(), 1);
    await page.locator("#reset").click();
    await page.locator('.comparison-counts button[data-status="persistent"]').click();
    assert.equal(await visible(), 3);
    await page.locator("#reset").click();
    await page.locator("#channel").selectOption("1001");
    assert.equal(await visible(), 2);
    await page.locator("#reset").click();
    await page.locator("#role").selectOption("200");
    assert.equal(await visible(), 2);
    await page.locator("#reset").click();
    await page.locator("#rule").selectOption("everyone_global_elevated");
    assert.equal(await visible(), 1);
    await page.locator("#reset").click();
    await page.locator("#state").selectOption("accepted");
    assert.equal(await visible(), 1);
    await page.locator("#reset").click();
    await page.locator("#rule").selectOption("everyone_global_elevated");
    await page.locator(".finding:visible > details > summary").click();
    assert.equal(await page.locator(".finding:visible .recommendation").isVisible(), true);
    await page.locator("#reset").click();
    await page.keyboard.press("/");
    assert.equal(await page.evaluate(() => document.activeElement.id), "search");
    // Theme toggle flips and persists the explicit choice.
    const before = await page.evaluate(() => document.documentElement.dataset.theme);
    await page.locator("#theme-toggle").click();
    const after = await page.evaluate(() => document.documentElement.dataset.theme);
    assert.notEqual(before, after);
    // Project links open in a new tab without leaking the opener; they are never fetched by the page.
    const external = await page.locator('a[href^="https://"]').evaluateAll(links => links.map(a => [a.rel, a.target]));
    assert.ok(external.length >= 8);
    assert.ok(external.every(([rel, target]) => rel.includes("noopener") && target === "_blank"));
    assert.ok(await page.locator('a[href*="github.com/Kayvooo/ServerSentry"]').count() > 0);
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
