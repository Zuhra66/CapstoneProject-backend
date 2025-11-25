// routes/events.js
const express = require("express");
const router = express.Router();
const { Client } = require("@notionhq/client");

const notion = new Client({ auth: process.env.NOTION_TOKEN });
const eventsDbId = process.env.NOTION_EVENTS_DATABASE_ID;
console.log("Backend EVENTS DB ID:", eventsDbId);

// Helper to grab a single file URL from a Notion "files" property
function getSingleFileUrl(prop) {
  const file = prop?.files?.[0];
  if (!file) return null;

  if (file.type === "file") return file.file.url;
  if (file.type === "external") return file.external.url;
  return null;
}

// Helper to grab ALL file URLs from a Notion "files" property
function getAllFileUrls(prop) {
  const files = prop?.files || [];
  return files
    .map((file) => {
      if (file.type === "file") return file.file.url;
      if (file.type === "external") return file.external.url;
      return null;
    })
    .filter(Boolean);
}

/**
 * GET /api/events
 * Returns raw Notion pages (used by Events list)
 */
router.get("/", async (req, res) => {
  try {
    console.log("Querying Notion events DB:", eventsDbId);

    const response = await notion.databases.query({
      database_id: eventsDbId,
      filter: {
        property: "Published",
        checkbox: { equals: true },
      },
      sorts: [
        {
          property: "Event Date",
          direction: "ascending",
        },
      ],
    });

    console.log("Events query success. Count:", response.results.length);
    res.json(response.results);
  } catch (err) {
    console.error("Notion /api/events error:", err.body || err);
    res.status(500).json({ error: "Failed to fetch events" });
  }
});

/**
 * GET /api/events/:slug
 * Single event + images + blocks
 */
router.get("/:slug", async (req, res) => {
  const slug = req.params.slug;

  try {
    const query = await notion.databases.query({
      database_id: eventsDbId,
      filter: {
        property: "Slug (URL text)",
        rich_text: { equals: slug },
      },
    });

    const page = query.results[0];
    if (!page) {
      return res.status(404).json({ error: "Event not found" });
    }

    // Children blocks (text, etc.) – optional
    const blocksResp = await notion.blocks.children.list({
      block_id: page.id,
      page_size: 100,
    });

    // Thumbnail image (card image)
    const thumbProp = page.properties["Thumbnail"];
    const thumbnailUrl = getSingleFileUrl(thumbProp);

    // Gallery images (flyer, extra images, etc.)
    const galleryProp = page.properties["Gallery Images"];
    const galleryUrls = getAllFileUrls(galleryProp);

    res.json({
      page,
      blocks: blocksResp.results,
      thumbnailUrl,
      galleryUrls,
    });
  } catch (err) {
    console.error("Notion /api/events/:slug error:", err.body || err);
    res.status(500).json({ error: "Failed to fetch event" });
  }
});

module.exports = router;
