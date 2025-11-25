const express = require("express");
const router = express.Router();

const NOTION_TOKEN = process.env.NOTION_TOKEN;
const DATABASE_ID = process.env.NOTION_DATABASE_ID;
const NOTION_VERSION = process.env.NOTION_VERSION || "2022-06-28";

async function notionQueryDatabase(body) {
  const res = await fetch(`https://api.notion.com/v1/databases/${DATABASE_ID}/query`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${NOTION_TOKEN}`,
      "Notion-Version": NOTION_VERSION,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text();
    console.error("Notion query error:", res.status, text);
    throw new Error("Notion query failed");
  }

  return res.json();
}

async function notionGetBlocks(blockId) {
  const res = await fetch(
    `https://api.notion.com/v1/blocks/${blockId}/children?page_size=100`,
    {
      headers: {
        Authorization: `Bearer ${NOTION_TOKEN}`,
        "Notion-Version": NOTION_VERSION,
      },
    }
  );

  if (!res.ok) {
    const text = await res.text();
    console.error("Notion blocks error:", res.status, text);
    throw new Error("Notion blocks fetch failed");
  }

  return res.json();
}

/**
 * GET /api/blog
 * Returns all published posts
 */
router.get("/", async (req, res) => {
  try {
    console.log("Querying Notion database:", DATABASE_ID);

    const data = await notionQueryDatabase({
      filter: {
        property: "Published", // checkbox in Notion
        checkbox: { equals: true },
      },
      sorts: [
        {
          property: "Publish Date", // date in Notion
          direction: "descending",
        },
      ],
    });

    res.json(data.results);
  } catch (err) {
    console.error("Notion /api/blog error:", err);
    res.status(500).json({ error: "Failed to fetch posts" });
  }
});

/**
 * GET /api/blog/:slug
 * Returns one post + its content blocks
 */
router.get("/:slug", async (req, res) => {
  const slug = req.params.slug;

  try {
    const data = await notionQueryDatabase({
      filter: {
        property: "Slug (URL text)", // rich_text column in Notion
        rich_text: { equals: slug },
      },
    });

    const page = data.results[0];
    if (!page) {
      return res.status(404).json({ error: "Post not found" });
    }

    const blocksData = await notionGetBlocks(page.id);

    res.json({ page, blocks: blocksData.results });
  } catch (err) {
    console.error("Notion /api/blog/:slug error:", err);
    res.status(500).json({ error: "Failed to fetch post" });
  }
});

module.exports = router;
