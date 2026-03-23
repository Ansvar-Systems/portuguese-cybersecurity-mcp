/**
 * Ingestion crawler for the CNCS (Centro Nacional de Ciberseguranca) MCP server.
 *
 * Crawls cncs.gov.pt for:
 *   1. Security alerts from CERT.PT  (dyn.cncs.gov.pt/pt/alertas)
 *   2. Technical recommendations      (cncs.gov.pt/pt/recomendacoes-tecnicas/)
 *   3. Guides and reference frameworks (cncs.gov.pt/pt/guias-referenciais/)
 *   4. Best practices documents        (dyn.cncs.gov.pt/pt/boaspraticas)
 *
 * Content is stored in Portuguese, matching the CNCS source language.
 *
 * Usage:
 *   npx tsx scripts/ingest-cncs.ts
 *   npx tsx scripts/ingest-cncs.ts --dry-run    # crawl without writing to DB
 *   npx tsx scripts/ingest-cncs.ts --resume     # skip already-ingested references
 *   npx tsx scripts/ingest-cncs.ts --force      # drop existing data and re-ingest
 *   npx tsx scripts/ingest-cncs.ts --resume --dry-run
 */

import Database from "better-sqlite3";
import * as cheerio from "cheerio";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["CNCS_DB_PATH"] ?? "data/cncs.db";
const RATE_LIMIT_MS = 1_500;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 3_000;
const REQUEST_TIMEOUT_MS = 30_000;
const USER_AGENT =
  "AnsvarCNCSCrawler/1.0 (+https://ansvar.eu; cybersecurity research)";

const BASE_URL = "https://www.cncs.gov.pt";
const DYN_BASE_URL = "https://dyn.cncs.gov.pt";

// Alerts use 0-indexed pagination; 259 items / ~20 per page = ~13 pages.
// Over-estimate to be safe; the crawler stops when a page returns no results.
const ALERTS_MAX_PAGES = 20;
const BEST_PRACTICES_MAX_PAGES = 10;

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const DRY_RUN = args.includes("--dry-run");
const RESUME = args.includes("--resume");
const FORCE = args.includes("--force");

if (DRY_RUN) console.log("[mode] dry-run — no database writes");
if (RESUME) console.log("[mode] resume — skipping existing references");
if (FORCE) console.log("[mode] force — dropping existing data first");

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

const dir = dirname(DB_PATH);
if (!existsSync(dir)) {
  mkdirSync(dir, { recursive: true });
}

if (FORCE && existsSync(DB_PATH)) {
  unlinkSync(DB_PATH);
  console.log(`Deleted existing database at ${DB_PATH}`);
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);
console.log(`Database ready at ${DB_PATH}`);

// ---------------------------------------------------------------------------
// Prepared statements
// ---------------------------------------------------------------------------

const insertAdvisory = db.prepare(`
  INSERT OR REPLACE INTO advisories
    (reference, title, date, severity, affected_products, summary, full_text, cve_references)
  VALUES
    (@reference, @title, @date, @severity, @affected_products, @summary, @full_text, @cve_references)
`);

const insertGuidance = db.prepare(`
  INSERT OR REPLACE INTO guidance
    (reference, title, title_en, date, type, series, summary, full_text, topics, status)
  VALUES
    (@reference, @title, @title_en, @date, @type, @series, @summary, @full_text, @topics, @status)
`);

const insertFramework = db.prepare(`
  INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count)
  VALUES (@id, @name, @name_en, @description, @document_count)
`);

const existsAdvisory = db.prepare(
  "SELECT 1 FROM advisories WHERE reference = ? LIMIT 1",
);
const existsGuidance = db.prepare(
  "SELECT 1 FROM guidance WHERE reference = ? LIMIT 1",
);

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithRetry(
  url: string,
  retries = MAX_RETRIES,
): Promise<string> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        REQUEST_TIMEOUT_MS,
      );

      const res = await fetch(url, {
        headers: {
          "User-Agent": USER_AGENT,
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9",
          "Accept-Language": "pt-PT,pt;q=0.9,en;q=0.5",
        },
        signal: controller.signal,
        redirect: "follow",
      });

      clearTimeout(timeout);

      if (!res.ok) {
        throw new Error(`HTTP ${res.status} for ${url}`);
      }

      return await res.text();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(
        `  [retry ${attempt}/${retries}] ${url} — ${msg}`,
      );
      if (attempt < retries) {
        await sleep(RETRY_BACKOFF_MS * attempt);
      } else {
        throw new Error(`Failed after ${retries} attempts: ${url}`);
      }
    }
  }
  throw new Error("unreachable");
}

async function fetchHtml(url: string): Promise<cheerio.CheerioAPI> {
  const html = await fetchWithRetry(url);
  return cheerio.load(html);
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

const stats = {
  advisories: { crawled: 0, inserted: 0, skipped: 0, errors: 0 },
  guidance: { crawled: 0, inserted: 0, skipped: 0, errors: 0 },
  frameworks: { inserted: 0 },
};

// ---------------------------------------------------------------------------
// Portuguese month map
// ---------------------------------------------------------------------------

const PT_MONTHS: Record<string, string> = {
  jan: "01",
  fev: "02",
  mar: "03",
  abr: "04",
  mai: "05",
  jun: "06",
  jul: "07",
  ago: "08",
  set: "09",
  out: "10",
  nov: "11",
  dez: "12",
};

/**
 * Parse dates like "20 Mar 2026" or "14/06/2019" into ISO YYYY-MM-DD.
 */
function parseDate(raw: string | undefined | null): string | null {
  if (!raw) return null;
  const trimmed = raw.trim();

  // "DD Mon YYYY" format used in alerts
  const match1 = trimmed.match(/^(\d{1,2})\s+(\w{3})\s+(\d{4})$/i);
  if (match1) {
    const [, day, monthStr, year] = match1;
    const month = PT_MONTHS[monthStr!.toLowerCase().slice(0, 3)];
    if (month && day && year) {
      return `${year}-${month}-${day.padStart(2, "0")}`;
    }
  }

  // "DD/MM/YYYY" format
  const match2 = trimmed.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (match2) {
    const [, day, month, year] = match2;
    if (day && month && year) {
      return `${year}-${month.padStart(2, "0")}-${day.padStart(2, "0")}`;
    }
  }

  // "DD-MM-YYYY" format
  const match3 = trimmed.match(/^(\d{1,2})-(\d{1,2})-(\d{4})$/);
  if (match3) {
    const [, day, month, year] = match3;
    if (day && month && year) {
      return `${year}-${month.padStart(2, "0")}-${day.padStart(2, "0")}`;
    }
  }

  // Already YYYY-MM-DD
  if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) return trimmed;

  return null;
}

// ---------------------------------------------------------------------------
// 1. Alerts (CERT.PT security advisories)
// ---------------------------------------------------------------------------

interface AlertListItem {
  url: string;
  title: string;
  date: string | null;
  type: string | null;
  systemsAffected: string | null;
  ecosystem: string | null;
}

/**
 * Parse the alerts listing page and extract individual alert links.
 */
function parseAlertsListing($: cheerio.CheerioAPI): AlertListItem[] {
  const items: AlertListItem[] = [];

  // Alerts are listed as linked blocks containing h2/h3 with date, title,
  // and metadata divs for TIPO, SISTEMAS AFETADOS, ECOSSISTEMA.
  // Link pattern: //dyn.cncs.gov.pt/pt/alerta-detalhe/art/<id>/<slug>
  $("a[href*='alerta-detalhe']").each((_i, el) => {
    const $el = $(el);
    let href = $el.attr("href");
    if (!href) return;

    // Normalise protocol-relative URLs
    if (href.startsWith("//")) href = "https:" + href;
    if (!href.startsWith("http")) href = DYN_BASE_URL + href;

    // Find title and date from sibling/parent context
    const parent = $el.parent();
    const titleEl = parent.find("h2").first();
    const dateEl = parent.find("h3").first();

    const title = titleEl.length
      ? titleEl.text().trim()
      : $el.text().trim().split("\n")[0]!.trim();
    const dateText = dateEl.length ? dateEl.text().trim() : null;

    // Extract metadata divs within the link
    const text = $el.text();
    const tipoMatch = text.match(/TIPO:\s*(.+?)(?:\n|SISTEMAS)/i);
    const sistemasMatch = text.match(/SISTEMAS AFETADOS:\s*(.+?)(?:\n|ECOSSISTEMA)/i);
    const ecoMatch = text.match(/ECOSSISTEMA:\s*(.+?)$/im);

    items.push({
      url: href,
      title: title || "Sem titulo",
      date: parseDate(dateText),
      type: tipoMatch ? tipoMatch[1]!.trim() : null,
      systemsAffected: sistemasMatch ? sistemasMatch[1]!.trim() : null,
      ecosystem: ecoMatch ? ecoMatch[1]!.trim() : null,
    });
  });

  return items;
}

/**
 * Extract the reference ID from an alert detail URL.
 * URL format: .../alerta-detalhe/art/<id>/<slug>
 */
function alertRefFromUrl(url: string): string {
  const match = url.match(/\/art\/(\d+)\//);
  return match ? `CERT-PT-${match[1]}` : `CERT-PT-${Date.now()}`;
}

/**
 * Determine severity from alert title and content.
 * CNCS does not always assign explicit severity — infer from keywords.
 */
function inferSeverity(title: string, text: string): string {
  const combined = (title + " " + text).toLowerCase();
  if (combined.includes("critico") || combined.includes("crítico")) return "critical";
  if (combined.includes("elevad") || combined.includes("alta")) return "high";
  if (combined.includes("medi") || combined.includes("moderado")) return "medium";
  if (combined.includes("baixo") || combined.includes("informativ")) return "low";
  // Vulnerability alerts default to high; code malicioso defaults to high
  if (combined.includes("vulnerabilidade")) return "high";
  if (combined.includes("código malicioso") || combined.includes("codigo malicioso")) return "high";
  return "medium";
}

/**
 * Extract CVE references from text.
 */
function extractCves(text: string): string[] {
  const matches = text.match(/CVE-\d{4}-\d{4,}/gi);
  return matches ? [...new Set(matches.map((c) => c.toUpperCase()))] : [];
}

/**
 * Crawl a single alert detail page and insert into the advisories table.
 */
async function crawlAlertDetail(item: AlertListItem): Promise<void> {
  const reference = alertRefFromUrl(item.url);

  if (RESUME && existsAdvisory.get(reference)) {
    stats.advisories.skipped++;
    return;
  }

  stats.advisories.crawled++;

  try {
    const $ = await fetchHtml(item.url);

    // Extract structured sections from the detail page.
    // Sections: Descricao, Impacto, Resolucao, Produtos Afetados, Referências
    const sections: string[] = [];
    let affectedProducts: string[] = [];
    let summary = "";

    // Try to pull the description section
    const bodyText = $("article, .content, .main-content, main, .post-content, body")
      .first()
      .text()
      .trim();

    // Extract section text by headings
    $("h2, h3, h4, strong").each((_i, el) => {
      const heading = $(el).text().trim().toLowerCase();
      const sectionText = $(el).nextUntil("h2, h3, h4, strong").text().trim();

      if (heading.includes("descri")) {
        summary = sectionText.slice(0, 500);
        sections.push(`Descricao:\n${sectionText}`);
      } else if (heading.includes("impacto")) {
        sections.push(`Impacto:\n${sectionText}`);
      } else if (heading.includes("resolu") || heading.includes("recomenda")) {
        sections.push(`Resolucao:\n${sectionText}`);
      } else if (
        heading.includes("produto") ||
        heading.includes("sistema") ||
        heading.includes("afetad")
      ) {
        // Collect affected product names from table rows or list items
        $(el)
          .nextUntil("h2, h3, h4")
          .find("tr, li")
          .each((_j, row) => {
            const rowText = $(row).text().trim();
            if (rowText && !rowText.toLowerCase().startsWith("produto")) {
              affectedProducts.push(rowText);
            }
          });
        if (affectedProducts.length === 0 && sectionText) {
          affectedProducts = sectionText
            .split("\n")
            .map((l) => l.trim())
            .filter(Boolean);
        }
        sections.push(`Produtos Afetados:\n${sectionText}`);
      } else if (heading.includes("refer")) {
        sections.push(`Referencias:\n${sectionText}`);
      }
    });

    const fullText =
      sections.length > 0
        ? sections.join("\n\n")
        : bodyText.slice(0, 10_000);

    if (!summary) {
      summary = fullText.slice(0, 500);
    }

    const cves = extractCves(fullText + " " + item.title);
    const severity = inferSeverity(item.title, fullText);

    // Prefer the title from the detail page if it is richer
    const detailTitle =
      $("h1").first().text().trim() || $("h2").first().text().trim();
    const title =
      detailTitle && detailTitle.length > 10 ? detailTitle : item.title;

    const row = {
      reference,
      title,
      date: item.date,
      severity,
      affected_products:
        affectedProducts.length > 0
          ? JSON.stringify(affectedProducts)
          : item.systemsAffected
            ? JSON.stringify([item.systemsAffected])
            : null,
      summary,
      full_text: fullText,
      cve_references:
        cves.length > 0 ? JSON.stringify(cves) : null,
    };

    if (!DRY_RUN) {
      insertAdvisory.run(row);
    }
    stats.advisories.inserted++;
    console.log(
      `  [advisory] ${reference} — ${title.slice(0, 60)}${DRY_RUN ? " (dry)" : ""}`,
    );
  } catch (err) {
    stats.advisories.errors++;
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  [error] advisory ${reference}: ${msg}`);
  }
}

/**
 * Crawl all alert pages.
 */
async function crawlAlerts(): Promise<void> {
  console.log("\n=== Crawling CERT.PT Security Alerts ===");

  for (let page = 0; page < ALERTS_MAX_PAGES; page++) {
    const url = `${DYN_BASE_URL}/pt/alertas/?page=${page}`;
    console.log(`\n[alerts] page ${page + 1} — ${url}`);

    try {
      const $ = await fetchHtml(url);
      const items = parseAlertsListing($);

      if (items.length === 0) {
        console.log(`[alerts] No items on page ${page + 1}. Stopping.`);
        break;
      }

      console.log(`[alerts] Found ${items.length} alerts on page ${page + 1}`);

      for (const item of items) {
        await sleep(RATE_LIMIT_MS);
        await crawlAlertDetail(item);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[alerts] Failed to fetch page ${page + 1}: ${msg}`);
    }

    await sleep(RATE_LIMIT_MS);
  }
}

// ---------------------------------------------------------------------------
// 2. Technical Recommendations (guidance)
// ---------------------------------------------------------------------------

interface RecommendationLink {
  url: string;
  pdfUrl: string | null;
  title: string;
  reference: string;
}

/**
 * Parse the technical recommendations listing page.
 */
function parseRecommendationsListing(
  $: cheerio.CheerioAPI,
): RecommendationLink[] {
  const items: RecommendationLink[] = [];

  // Each recommendation has a heading with the reference code and a "LER MAIS +"
  // link or a direct PDF link.
  $("a[href*='recomendacao-tecnica'], a[href*='cncs-rt']").each((_i, el) => {
    const $el = $(el);
    let href = $el.attr("href") ?? "";

    // Normalise relative URLs
    if (href.startsWith("../")) {
      href = BASE_URL + href.replace(/^(?:\.\.\/)+/, "/");
    }
    if (!href.startsWith("http")) {
      href = BASE_URL + (href.startsWith("/") ? "" : "/") + href;
    }

    const isPdf = href.toLowerCase().endsWith(".pdf");
    const text = $el.closest("div, section, article").text().trim();

    // Extract reference like "RT 01/2021" or "RECOMENDACAO TECNICA 01/2020"
    const refMatch = text.match(
      /(?:RECOMENDA[CÇ][AÃ]O\s+T[EÉ]CNICA|RT)\s+(\d+\/\d{4})/i,
    );
    const reference = refMatch ? `CNCS-RT-${refMatch[1]}` : `CNCS-RT-${Date.now()}`;

    // Try to get title from heading
    const heading =
      $el.closest("div, section").find("h2, h3, h4").first().text().trim() ||
      $el.text().trim();

    items.push({
      url: isPdf ? href : href,
      pdfUrl: isPdf ? href : null,
      title: heading || "Recomendacao Tecnica",
      reference,
    });
  });

  // Deduplicate by reference
  const seen = new Set<string>();
  return items.filter((item) => {
    if (seen.has(item.reference)) return false;
    seen.add(item.reference);
    return true;
  });
}

/**
 * Crawl a single technical recommendation page and insert as guidance.
 */
async function crawlRecommendation(item: RecommendationLink): Promise<void> {
  if (RESUME && existsGuidance.get(item.reference)) {
    stats.guidance.skipped++;
    return;
  }

  stats.guidance.crawled++;

  try {
    let fullText = "";
    let date: string | null = null;
    let title = item.title;
    const topics: string[] = [];

    if (item.pdfUrl) {
      // For PDFs, store the URL reference — we cannot parse PDFs with cheerio.
      // The detail page (if one exists) is used instead.
      fullText = `[Documento PDF disponivel em: ${item.pdfUrl}]`;
    }

    // Try to fetch the HTML detail page
    const detailUrl = item.url.endsWith(".pdf") ? null : item.url;
    if (detailUrl) {
      const $ = await fetchHtml(detailUrl);

      const pageTitle = $("h1, h2").first().text().trim();
      if (pageTitle && pageTitle.length > 5) title = pageTitle;

      // Look for date metadata
      const dateText = $("body")
        .text()
        .match(
          /(?:Data|Vers[aã]o|Atualiza[çc][aã]o)[^:]*:\s*(\d{1,2}[/-]\d{1,2}[/-]\d{4})/i,
        );
      if (dateText) {
        date = parseDate(dateText[1]);
      }

      // Extract main body content
      const mainContent = $(
        "article, .content, .main-content, .entry-content, main",
      ).first();
      const contentEl = mainContent.length ? mainContent : $("body");
      fullText = contentEl
        .find("p, li, h2, h3, h4, h5, td")
        .map((_j, p) => $(p).text().trim())
        .get()
        .filter(Boolean)
        .join("\n\n");

      // Extract topic keywords from content
      const topicKeywords = [
        "SPF", "DKIM", "DMARC", "email", "DNS", "TLS", "HTTPS",
        "autenticacao", "criptografia", "vulnerabilidade", "rede",
        "certificado", "STARTTLS", "DANE", "dominio",
      ];
      for (const kw of topicKeywords) {
        if (fullText.toLowerCase().includes(kw.toLowerCase())) {
          topics.push(kw.toLowerCase());
        }
      }

      // Look for PDF link on the page
      if (!item.pdfUrl) {
        const pdfLink = $("a[href$='.pdf']").first().attr("href");
        if (pdfLink) {
          const pdfAbsolute = pdfLink.startsWith("http")
            ? pdfLink
            : BASE_URL + pdfLink.replace(/^(?:\.\.\/)+/, "/");
          fullText += `\n\n[Documento PDF: ${pdfAbsolute}]`;
        }
      }
    }

    if (!fullText || fullText.length < 20) {
      console.warn(
        `  [skip] ${item.reference} — insufficient content`,
      );
      stats.guidance.errors++;
      return;
    }

    const summary = fullText.slice(0, 500);

    const row = {
      reference: item.reference,
      title,
      title_en: null,
      date,
      type: "technical_recommendation",
      series: "CNCS-RT",
      summary,
      full_text: fullText,
      topics: topics.length > 0 ? JSON.stringify(topics) : null,
      status: "current",
    };

    if (!DRY_RUN) {
      insertGuidance.run(row);
    }
    stats.guidance.inserted++;
    console.log(
      `  [guidance] ${item.reference} — ${title.slice(0, 60)}${DRY_RUN ? " (dry)" : ""}`,
    );
  } catch (err) {
    stats.guidance.errors++;
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  [error] guidance ${item.reference}: ${msg}`);
  }
}

/**
 * Crawl the technical recommendations listing.
 */
async function crawlRecommendations(): Promise<void> {
  console.log("\n=== Crawling Technical Recommendations ===");

  const url = `${BASE_URL}/pt/recomendacoes-tecnicas/`;
  console.log(`[recommendations] ${url}`);

  try {
    const $ = await fetchHtml(url);
    const items = parseRecommendationsListing($);
    console.log(`[recommendations] Found ${items.length} items`);

    for (const item of items) {
      await sleep(RATE_LIMIT_MS);
      await crawlRecommendation(item);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[recommendations] Failed: ${msg}`);
  }
}

// ---------------------------------------------------------------------------
// 3. Guides and Reference Frameworks (guidance + frameworks)
// ---------------------------------------------------------------------------

interface GuideLink {
  url: string;
  title: string;
  slug: string;
}

/**
 * Parse the guides and references listing page.
 */
function parseGuidesListing($: cheerio.CheerioAPI): GuideLink[] {
  const items: GuideLink[] = [];

  // Each guide is a card with an "LER MAIS +" link to the detail page.
  // URLs like: /pt/gestao-de-risco/, /pt/guia-mfa/, /pt/guia-de-transicao-digital/
  $("a[href*='/pt/']").each((_i, el) => {
    const $el = $(el);
    let href = $el.attr("href") ?? "";
    const text = $el.text().trim();

    // Only follow "LER MAIS" or guide-like links within the content area
    const isReadMore = text.toLowerCase().includes("ler mais");
    const isGuideUrl =
      href.includes("gestao-de-risco") ||
      href.includes("guia-mfa") ||
      href.includes("guia-de-transicao-digital") ||
      href.includes("referencial-de-competencias") ||
      href.includes("referencial-de-comunicacao");

    if (!isReadMore && !isGuideUrl) return;

    if (!href.startsWith("http")) {
      href = BASE_URL + (href.startsWith("/") ? "" : "/") + href;
    }

    // Extract title from parent heading
    const heading = $el
      .closest("div, section, article")
      .find("h2, h3, h4")
      .first()
      .text()
      .trim();

    // Derive slug from URL
    const slugMatch = href.match(/\/pt\/([^/?]+)/);
    const slug = slugMatch ? slugMatch[1]! : `guide-${Date.now()}`;

    items.push({
      url: href,
      title: heading || text || "Guia CNCS",
      slug,
    });
  });

  // Deduplicate by slug
  const seen = new Set<string>();
  return items.filter((item) => {
    if (seen.has(item.slug)) return false;
    seen.add(item.slug);
    return true;
  });
}

/**
 * Crawl a single guide detail page.
 */
async function crawlGuide(item: GuideLink): Promise<void> {
  const reference = `CNCS-GUIDE-${item.slug}`;

  if (RESUME && existsGuidance.get(reference)) {
    stats.guidance.skipped++;
    return;
  }

  stats.guidance.crawled++;

  try {
    const $ = await fetchHtml(item.url);

    const pageTitle = $("h1, h2").first().text().trim();
    const title =
      pageTitle && pageTitle.length > 5 ? pageTitle : item.title;

    // Extract main content
    const mainContent = $(
      "article, .content, .main-content, .entry-content, main",
    ).first();
    const contentEl = mainContent.length ? mainContent : $("body");

    const paragraphs = contentEl
      .find("p, li, h2, h3, h4, h5, td, th")
      .map((_j, p) => $(p).text().trim())
      .get()
      .filter(Boolean);

    const fullText = paragraphs.join("\n\n");

    if (fullText.length < 50) {
      console.warn(`  [skip] ${reference} — insufficient content`);
      stats.guidance.errors++;
      return;
    }

    // Look for PDF download links
    const pdfLinks: string[] = [];
    $("a[href$='.pdf']").each((_j, pdfEl) => {
      let pdfHref = $(pdfEl).attr("href") ?? "";
      if (pdfHref.startsWith("../")) {
        pdfHref = BASE_URL + pdfHref.replace(/^(?:\.\.\/)+/, "/");
      }
      if (!pdfHref.startsWith("http")) {
        pdfHref = BASE_URL + (pdfHref.startsWith("/") ? "" : "/") + pdfHref;
      }
      pdfLinks.push(pdfHref);
    });

    const fullTextWithPdfs =
      pdfLinks.length > 0
        ? fullText + "\n\n[Documentos PDF: " + pdfLinks.join(", ") + "]"
        : fullText;

    // Determine guide type
    let type = "guide";
    if (item.slug.includes("referencial")) type = "framework_reference";
    if (item.slug.includes("gestao-de-risco")) type = "risk_management";
    if (item.slug.includes("mfa")) type = "technical_guideline";
    if (item.slug.includes("transicao-digital")) type = "sector_guide";

    // Look for date
    const dateText = $("body")
      .text()
      .match(/(?:Atualiza[çc][aã]o|Data|Publica[çc][aã]o)[^:]*:\s*(\d{1,2}[/-]\d{1,2}[/-]\d{4})/i);
    const date = dateText ? parseDate(dateText[1]) : null;

    const summary = fullText.slice(0, 500);

    // Determine topics from content
    const topicKeywords: Record<string, string> = {
      "gestao de riscos": "gestao de riscos",
      "risco": "risco",
      "autenticacao": "autenticacao",
      "mfa": "MFA",
      "multifator": "MFA",
      "transicao digital": "transicao digital",
      "competencias": "competencias",
      "comunicacao": "comunicacao de crise",
      "formacao": "formacao",
      "rgpd": "RGPD",
      "nis2": "NIS2",
      "nist": "NIST",
      "iso 27": "ISO 27001",
    };
    const topics: string[] = [];
    const lowerText = fullText.toLowerCase();
    for (const [keyword, topic] of Object.entries(topicKeywords)) {
      if (lowerText.includes(keyword) && !topics.includes(topic)) {
        topics.push(topic);
      }
    }

    const row = {
      reference,
      title,
      title_en: null,
      date,
      type,
      series: "CNCS-Guias",
      summary,
      full_text: fullTextWithPdfs,
      topics: topics.length > 0 ? JSON.stringify(topics) : null,
      status: "current",
    };

    if (!DRY_RUN) {
      insertGuidance.run(row);
    }
    stats.guidance.inserted++;
    console.log(
      `  [guidance] ${reference} — ${title.slice(0, 60)}${DRY_RUN ? " (dry)" : ""}`,
    );
  } catch (err) {
    stats.guidance.errors++;
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  [error] guidance ${reference}: ${msg}`);
  }
}

/**
 * Crawl guides and reference frameworks listing.
 */
async function crawlGuides(): Promise<void> {
  console.log("\n=== Crawling Guides and Reference Frameworks ===");

  const url = `${BASE_URL}/pt/guias-referenciais/`;
  console.log(`[guides] ${url}`);

  try {
    const $ = await fetchHtml(url);
    const items = parseGuidesListing($);
    console.log(`[guides] Found ${items.length} guide links`);

    for (const item of items) {
      await sleep(RATE_LIMIT_MS);
      await crawlGuide(item);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[guides] Failed: ${msg}`);
  }
}

// ---------------------------------------------------------------------------
// 4. Best Practices documents (guidance)
// ---------------------------------------------------------------------------

interface BestPracticeItem {
  url: string;
  pdfUrl: string | null;
  title: string;
  date: string | null;
  categories: string[];
  resourceType: string | null;
}

/**
 * Parse the best practices listing page.
 */
function parseBestPracticesListing(
  $: cheerio.CheerioAPI,
): BestPracticeItem[] {
  const items: BestPracticeItem[] = [];

  // Best practice cards contain a title, date, category tags, resource type,
  // and a link (PDF download or "Ver Mais" detail page).
  // Look for cards by their link structure.
  $("a[href*='.pdf'], a[href*='/pt/']").each((_i, el) => {
    const $el = $(el);
    let href = $el.attr("href") ?? "";
    const linkText = $el.text().trim().toLowerCase();

    // Only follow download/view-more links
    if (
      !linkText.includes("download") &&
      !linkText.includes("ver mais") &&
      !href.endsWith(".pdf")
    ) {
      return;
    }

    // Normalise URL
    if (href.startsWith("//")) href = "https:" + href;
    if (!href.startsWith("http")) {
      href = BASE_URL + (href.startsWith("/") ? "" : "/") + href;
    }

    // Navigate up to the card container
    const card = $el.closest("div, article, section, li");

    // Extract title (usually in h2/h3/h4 or a strong tag)
    const heading = card.find("h2, h3, h4, strong").first().text().trim();
    const title = heading || "Boas Praticas CNCS";

    // Extract date
    const cardText = card.text();
    const dateMatch = cardText.match(/(\d{1,2}\s+\w{3}\s+\d{4})/);
    const date = dateMatch ? parseDate(dateMatch[1]) : null;

    // Extract categories from tag-like elements
    const categories: string[] = [];
    card.find("span, .tag, .category, .badge").each((_j, tag) => {
      const tagText = $(tag).text().trim();
      if (tagText && tagText.length > 2 && tagText.length < 50) {
        categories.push(tagText);
      }
    });

    // Determine resource type
    let resourceType: string | null = null;
    const rtMatch = cardText.match(
      /(?:Cartazes|Documentos|Tutoriais|Videos|Vídeos|Artigos|Podcasts)/i,
    );
    if (rtMatch) resourceType = rtMatch[0]!.toLowerCase();

    const isPdf = href.toLowerCase().endsWith(".pdf");

    items.push({
      url: href,
      pdfUrl: isPdf ? href : null,
      title,
      date,
      categories,
      resourceType,
    });
  });

  // Deduplicate by URL
  const seen = new Set<string>();
  return items.filter((item) => {
    if (seen.has(item.url)) return false;
    seen.add(item.url);
    return true;
  });
}

/**
 * Crawl a single best practice item.
 */
async function crawlBestPractice(
  item: BestPracticeItem,
  index: number,
): Promise<void> {
  // Generate a stable reference from the URL or title
  const slug = item.url
    .replace(/^https?:\/\/[^/]+/, "")
    .replace(/[^a-zA-Z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 80);
  const reference = `CNCS-BP-${slug || index}`;

  if (RESUME && existsGuidance.get(reference)) {
    stats.guidance.skipped++;
    return;
  }

  stats.guidance.crawled++;

  try {
    let fullText = "";
    let title = item.title;

    if (item.pdfUrl) {
      // PDF — store reference to the document
      fullText = `${item.title}\n\n[Documento PDF disponivel em: ${item.pdfUrl}]`;
      if (item.categories.length > 0) {
        fullText += `\n\nCategorias: ${item.categories.join(", ")}`;
      }
    } else {
      // HTML page — fetch and extract content
      const $ = await fetchHtml(item.url);

      const pageTitle = $("h1, h2").first().text().trim();
      if (pageTitle && pageTitle.length > 5) title = pageTitle;

      const mainContent = $(
        "article, .content, .main-content, .entry-content, main",
      ).first();
      const contentEl = mainContent.length ? mainContent : $("body");

      fullText = contentEl
        .find("p, li, h2, h3, h4, h5, td")
        .map((_j, p) => $(p).text().trim())
        .get()
        .filter(Boolean)
        .join("\n\n");

      // Collect PDF links on the page
      const pdfLinks: string[] = [];
      $("a[href$='.pdf']").each((_j, pdfEl) => {
        let pdfHref = $(pdfEl).attr("href") ?? "";
        if (!pdfHref.startsWith("http")) {
          pdfHref = BASE_URL + pdfHref.replace(/^(?:\.\.\/)+/, "/");
        }
        pdfLinks.push(pdfHref);
      });
      if (pdfLinks.length > 0) {
        fullText += `\n\n[Documentos PDF: ${pdfLinks.join(", ")}]`;
      }
    }

    if (!fullText || fullText.length < 20) {
      stats.guidance.errors++;
      return;
    }

    const summary = fullText.slice(0, 500);

    const topics = item.categories.length > 0
      ? JSON.stringify(item.categories)
      : null;

    const row = {
      reference,
      title,
      title_en: null,
      date: item.date,
      type: item.resourceType ?? "best_practice",
      series: "CNCS-BP",
      summary,
      full_text: fullText,
      topics,
      status: "current",
    };

    if (!DRY_RUN) {
      insertGuidance.run(row);
    }
    stats.guidance.inserted++;
    console.log(
      `  [guidance] ${reference} — ${title.slice(0, 60)}${DRY_RUN ? " (dry)" : ""}`,
    );
  } catch (err) {
    stats.guidance.errors++;
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  [error] guidance ${reference}: ${msg}`);
  }
}

/**
 * Crawl all best practice pages.
 */
async function crawlBestPractices(): Promise<void> {
  console.log("\n=== Crawling Best Practices ===");

  for (let page = 0; page < BEST_PRACTICES_MAX_PAGES; page++) {
    const url =
      page === 0
        ? `${DYN_BASE_URL}/pt/boaspraticas`
        : `${DYN_BASE_URL}/pt/boaspraticas?page=${page}`;
    console.log(`\n[best-practices] page ${page + 1} — ${url}`);

    try {
      const $ = await fetchHtml(url);
      const items = parseBestPracticesListing($);

      if (items.length === 0) {
        console.log(
          `[best-practices] No items on page ${page + 1}. Stopping.`,
        );
        break;
      }

      console.log(
        `[best-practices] Found ${items.length} items on page ${page + 1}`,
      );

      for (let i = 0; i < items.length; i++) {
        await sleep(RATE_LIMIT_MS);
        await crawlBestPractice(items[i]!, page * 20 + i);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(
        `[best-practices] Failed to fetch page ${page + 1}: ${msg}`,
      );
    }

    await sleep(RATE_LIMIT_MS);
  }
}

// ---------------------------------------------------------------------------
// 5. Seed the frameworks table
// ---------------------------------------------------------------------------

function seedFrameworks(): void {
  console.log("\n=== Seeding Frameworks ===");

  const frameworks = [
    {
      id: "qnrcs",
      name: "Quadro Nacional de Referencia para a Ciberseguranca (QNRCS)",
      name_en: "National Cybersecurity Reference Framework",
      description:
        "O QNRCS e o quadro de referencia nacional para a ciberseguranca em Portugal, alinhado com o NIST Cybersecurity Framework. Define tres niveis de capacidade (Inicial, Intermedio, Avancado) para cinco objetivos: identificar, proteger, detetar, responder e recuperar. Entidades podem aderir voluntariamente e obter certificacao.",
      document_count: 0, // updated after crawl
    },
    {
      id: "nis2-pt",
      name: "Implementacao da Diretiva NIS2 em Portugal",
      name_en: "NIS2 Directive Implementation in Portugal",
      description:
        "Orientacoes para a implementacao da Diretiva NIS2 (UE 2022/2555) em Portugal. O CNCS e a autoridade nacional de ciberseguranca responsavel pela supervisao. Inclui categorizacao de entidades essenciais e importantes, requisitos de seguranca (artigo 21), obrigacoes de notificacao de incidentes (artigo 23) e regime sancionatorio.",
      document_count: 0,
    },
    {
      id: "cncs-guidelines",
      name: "Guias Tecnicos CNCS",
      name_en: "CNCS Technical Guides",
      description:
        "Guias tecnicos e recomendacoes publicados pelo CNCS sobre temas de ciberseguranca: gestao de vulnerabilidades, seguranca de redes, autenticacao, criptografia, resposta a incidentes, seguranca em nuvem e transicao digital.",
      document_count: 0,
    },
    {
      id: "cncs-rt",
      name: "Recomendacoes Tecnicas CNCS",
      name_en: "CNCS Technical Recommendations",
      description:
        "Recomendacoes tecnicas associadas ao cumprimento de normas, boas praticas e configuracoes que contribuem para o aumento dos niveis de ciberseguranca nas organizacoes. Inclui recomendacoes sobre SPF, DKIM, DMARC, STARTTLS, DANE e protecao de dominios.",
      document_count: 0,
    },
    {
      id: "cert-pt",
      name: "CERT.PT — Equipa de Resposta a Incidentes",
      name_en: "CERT.PT — Computer Emergency Response Team",
      description:
        "O CERT.PT e a equipa de resposta a incidentes de seguranca informatica do CNCS. Membro do FIRST e acreditado pelo Trusted Introducer. Emite alertas de seguranca, coordena a resposta a incidentes e publica indicadores de compromisso (IoC).",
      document_count: 0,
    },
    {
      id: "cncs-bp",
      name: "Boas Praticas de Ciberseguranca",
      name_en: "Cybersecurity Best Practices",
      description:
        "Conteudos de sensibilizacao e boas praticas de ciberseguranca publicados pelo CNCS para cidadaos, empresas e administracao publica. Inclui cartazes, documentos, tutoriais, videos e artigos sobre temas como phishing, passwords, fraude, compras online e teletrabalho.",
      document_count: 0,
    },
  ];

  if (!DRY_RUN) {
    for (const f of frameworks) {
      insertFramework.run(f);
    }
  }
  stats.frameworks.inserted = frameworks.length;
  console.log(
    `Inserted ${frameworks.length} frameworks${DRY_RUN ? " (dry)" : ""}`,
  );
}

/**
 * Update framework document counts based on actual ingested guidance.
 */
function updateFrameworkCounts(): void {
  if (DRY_RUN) return;

  const seriesMap: Record<string, string> = {
    "CNCS-RT": "cncs-rt",
    "CNCS-Guias": "cncs-guidelines",
    "CNCS-BP": "cncs-bp",
    NIS2: "nis2-pt",
  };

  for (const [series, frameworkId] of Object.entries(seriesMap)) {
    const result = db
      .prepare("SELECT count(*) as cnt FROM guidance WHERE series = ?")
      .get(series) as { cnt: number } | undefined;
    if (result) {
      db.prepare("UPDATE frameworks SET document_count = ? WHERE id = ?").run(
        result.cnt,
        frameworkId,
      );
    }
  }

  // CERT.PT framework gets advisory count
  const advisoryCount = db
    .prepare("SELECT count(*) as cnt FROM advisories")
    .get() as { cnt: number } | undefined;
  if (advisoryCount) {
    db.prepare("UPDATE frameworks SET document_count = ? WHERE id = ?").run(
      advisoryCount.cnt,
      "cert-pt",
    );
  }

  // QNRCS gets total guidance count
  const totalGuidance = db
    .prepare("SELECT count(*) as cnt FROM guidance")
    .get() as { cnt: number } | undefined;
  if (totalGuidance) {
    db.prepare("UPDATE frameworks SET document_count = ? WHERE id = ?").run(
      totalGuidance.cnt,
      "qnrcs",
    );
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("CNCS Ingestion Crawler");
  console.log("=".repeat(60));
  console.log(`Target: ${BASE_URL} / ${DYN_BASE_URL}`);
  console.log(`Database: ${DB_PATH}`);
  console.log(`Rate limit: ${RATE_LIMIT_MS}ms between requests`);
  console.log(`Retry: ${MAX_RETRIES} attempts, ${RETRY_BACKOFF_MS}ms backoff`);
  console.log();

  seedFrameworks();

  await crawlAlerts();
  await crawlRecommendations();
  await crawlGuides();
  await crawlBestPractices();

  updateFrameworkCounts();

  // Final summary
  console.log("\n" + "=".repeat(60));
  console.log("Ingestion complete\n");
  console.log("  Advisories:");
  console.log(`    Crawled:  ${stats.advisories.crawled}`);
  console.log(`    Inserted: ${stats.advisories.inserted}`);
  console.log(`    Skipped:  ${stats.advisories.skipped}`);
  console.log(`    Errors:   ${stats.advisories.errors}`);
  console.log("  Guidance:");
  console.log(`    Crawled:  ${stats.guidance.crawled}`);
  console.log(`    Inserted: ${stats.guidance.inserted}`);
  console.log(`    Skipped:  ${stats.guidance.skipped}`);
  console.log(`    Errors:   ${stats.guidance.errors}`);
  console.log(`  Frameworks: ${stats.frameworks.inserted}`);

  if (!DRY_RUN) {
    const advisoryCount = (
      db.prepare("SELECT count(*) as cnt FROM advisories").get() as {
        cnt: number;
      }
    ).cnt;
    const guidanceCount = (
      db.prepare("SELECT count(*) as cnt FROM guidance").get() as {
        cnt: number;
      }
    ).cnt;
    const frameworkCount = (
      db.prepare("SELECT count(*) as cnt FROM frameworks").get() as {
        cnt: number;
      }
    ).cnt;

    console.log(`\nDatabase totals:`);
    console.log(`  Advisories:  ${advisoryCount}`);
    console.log(`  Guidance:    ${guidanceCount}`);
    console.log(`  Frameworks:  ${frameworkCount}`);
  }

  console.log(`\nDatabase at ${DB_PATH}`);
  db.close();
}

main().catch((err) => {
  console.error("Fatal error:", err);
  db.close();
  process.exit(1);
});
